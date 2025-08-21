#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

mod bpf_helper;
mod cli;
mod logger;
mod utils;

use anyhow::{Context as _, Result};
use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, MapData, PerCpuArray, PerCpuValues, RingBuf, XskMap},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use core::slice;
use log::{debug, error, info, trace, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use poc_common::Stat;
use std::{mem::MaybeUninit, net::Ipv4Addr};
use std::{
    mem::{self, offset_of},
    os::fd::AsRawFd,
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed},
        Arc, LazyLock,
    },
    time::Duration,
};
use tokio::{
    signal,
    time::{self},
};
use utils::{RX_QUEUE_SIZE, UMEM_SIZE};
use xdpilone::{xdp::XdpDesc, Umem, UmemConfig};

const QUEUE_ID: u32 = 0;

const BEE: &str = "poc_redirect_to_afxdp";

static RECV_PACKETS: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = cli::parse();

    logger::init();

    println!("=======================");
    println!("app:        {}", BEE);
    println!("log-level:  {}", log::max_level());
    println!("iface:      {}", args.iface);
    println!("=======================");

    let mut ebpf = init_bpf(&args.iface, BEE)?;

    let stat: PerCpuArray<MapData, Stat> =
        PerCpuArray::try_from(ebpf.take_map("STAT").expect("STAT-1")).expect("STAT-2");

    let start_time = utils::now_ns();
    let start_cpu_time = utils::cpu_time_ms();

    ///////////////////////////////////////////////////
    ///////////////////////////////////////////////////
    ///////////////////////////////////////////////////

    #[repr(C, align(4096))]
    struct PacketMap(MaybeUninit<[u8; UMEM_SIZE]>);

    let mut alloc = Box::new(PacketMap(MaybeUninit::zeroed()));
    let umem_ptr = unsafe { alloc.0.assume_init_mut() }.as_mut();
    let umem = unsafe { Umem::new(UmemConfig::default(), umem_ptr.into()) }.unwrap();

    let (mut rx, mut tx, mut dev) = utils::bind_xsk_umem(&args.iface, QUEUE_ID, &umem);

    let mut xsocks = XskMap::try_from(ebpf.take_map("XSOCKS").context("XSOCKS map not found")?)?;
    xsocks.set(QUEUE_ID, rx.as_raw_fd(), 0).unwrap();

    utils::fill_frames_for_kernel(&mut dev);
    info!("AF_XDP prepared Fill-Queue: {}", dev.pending());

    let mut was_rx_used = u32::MAX;
    let mut was_rx_free = u32::MAX;
    let mut was_dropped = 0;
    let mut counter = 0;
    let mut was_counter = 0;

    for _iii in 0..10000 {
        if was_rx_used != rx.available() || was_rx_free != dev.pending() {
            was_rx_used = rx.available();
            was_rx_free = dev.pending();
            assert!(!dev.needs_wakeup());
            debug!("RX (used/free): {}/{}", rx.available(), dev.pending());
        }
        if was_counter != counter {
            was_counter = counter;
            info!("Packets out: {:?}", counter);
        }
        if was_dropped != dev.statistics_v2().unwrap().rx_dropped {
            was_dropped = dev.statistics_v2().unwrap().rx_dropped;
            error!("Dropped: {:?}", dev.statistics_v2().unwrap().rx_dropped);
        }

        // READ
        let mut read_rx = rx.receive(RX_QUEUE_SIZE);

        while let Some(rx_desc) = read_rx.read() {
            let ptr_rx_u8 = &umem_ptr[rx_desc.addr as usize] as *const u8;
            print_packet(ptr_rx_u8, &rx_desc);

            // // tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

            // {
            //     let mut tx_writer = tx.transmit(1); // TX queue submission
            //     if tx_writer.insert_once(rx_desc) {
            //         let ptr_tx_u8 = &umem_ptr[rx_desc.addr as usize] as *const u8 as *mut u8;
            //         unsafe { std::ptr::copy_nonoverlapping(ptr_rx_u8, ptr_tx_u8, 190) };
            //     }
            //     tx_writer.commit(); // Commit to the kernel
            // }

            // assert!(tx.needs_wakeup());
            // tx.wake(); // Wake up the transmit queue

            // let mut tx_complete = dev.complete(1);
            // while let Some(tx_desc) = tx_complete.read() {
            //     counter += 1;
            // }

            // // FIXME: Correct sequence?
            // tx_complete.release();

            // // let mut writer = dev.fill(1);
            // // writer.insert_once(rx_desc.addr);
            // // writer.commit();
        }

        read_rx.release();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    info!("END =================================");
    info!("{:?}", dev.statistics_v2());

    ///////////////////////////////////////////////////
    ///////////////////////////////////////////////////
    ///////////////////////////////////////////////////

    // wait for the end
    if let Some(millis) = args.timeout {
        debug!("Waiting {} ms", millis);
        time::sleep(tokio::time::Duration::from_millis(millis)).await;
    } else {
        debug!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
    }

    let end_cpu_time = utils::cpu_time_ms();
    let end_time = utils::now_ns();

    let elapsed = (end_time - start_time) as f64 / 1_000_000_000.0;
    let sys_ms = (end_cpu_time.0 - start_cpu_time.0) as f64 / 1_000.0 / elapsed;
    let usr_ms = (end_cpu_time.1 - start_cpu_time.1) as f64 / 1_000.0 / elapsed;

    let stat = stat.get(&0, 0)?;

    print_report(&args, stat, elapsed, sys_ms, usr_ms);
    Ok(())
}

fn init_bpf(iface: &str, bee: &str) -> Result<Ebpf> {
    bpf_helper::legacy_memlock_rlimit_remove()?;

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/poc")))?;

    EbpfLogger::init(&mut ebpf).context("Init eBPF logger")?; // This can happen if you remove all log statements from your eBPF program.

    let program: &mut Xdp = ebpf.program_mut(bee).unwrap().try_into()?;
    program.load()?;
    program
        .attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    debug!("eBPF loaded: {bee}");
    Ok(ebpf)
}

fn print_report(args: &cli::Opt, stat: PerCpuValues<Stat>, elapsed: f64, sys_ms: f64, usr_ms: f64) {
    let total_packets = stat.iter().fold(0, |acc, x| acc + x.total_packets);
    let redir_packets = stat.iter().fold(0, |acc, x| acc + x.redir_packets);
    let redir_failed_packets = stat.iter().fold(0, |acc, x| acc + x.redir_failed_packets);

    RECV_PACKETS.store(total_packets, Relaxed);

    info!("************");
    info!("* received: {total_packets} pk");
    info!("* redirected: {redir_packets} pk");
    error!("* redir-fail: {redir_failed_packets} pk");

    // let latency_micro = latency_sum as f64 / recv_packets as f64 / 1000.0;
    // let pps = recv_packets as f64 / elapsed;

    // if latency_sum == 0 {
    //     info!("* Latency:    {latency_micro:9.0} µs/pk");
    // } else {
    //     warn!("* Latency:    {latency_micro:9.0} µs/pk");
    // }

    // if recv_packets == 0 {
    //     error!("* Throughput: {pps:9.0} pk/s  ({recv_packets} pk /  {elapsed:.3} s)");
    // } else if recv_packets > 10000 {
    //     let pps = pps / 1000.0;
    //     warn!("* Throughput: {pps:9.0} kpk/s  ({recv_packets:.0} pk / {elapsed:.3} s)");
    // } else {
    //     warn!("* Throughput: {pps:9.0} pk/s  ({recv_packets} pk /  {elapsed:.3} s)");
    // }

    // if lost_packets == 0 {
    //     info!("* Lost:       {lost_packets:9} pk");
    // } else {
    //     let lost_percent = 100.0 * LOST_PACKETS.load(Relaxed) as f64 / total_packets as f64;
    //     error!("* Lost:       {lost_percent:9.6} pk%  ({lost_packets:9} pk)");
    // }

    // info!("* Idle:       {idle_cycles:9} cycles");

    if sys_ms < 100.0 {
        info!("* CPU sys-time: {sys_ms:7.1} ms/s");
    } else {
        error!("* CPU sys-time: {sys_ms:7.1} ms/s");
    }

    if usr_ms < 100.0 {
        info!("* CPU usr-time: {usr_ms:7.1} ms/s");
    } else {
        error!("* CPU usr-time: {usr_ms:7.1} ms/s");
    }
    info!("************");
}

#[inline(always)]
unsafe fn read_unchecked<T>(pos: usize) -> T {
    let ptr = pos as *const T;
    unsafe { ptr.read_unaligned() }
}

fn print_packet(ptr: *const u8, desc: &XdpDesc) {
    let ptr_rx_u8 = ptr;
    let ptr_rx = ptr as usize;
    let ip4_ptr = ptr_rx + EthHdr::LEN;
    let udp_ptr = ip4_ptr + Ipv4Hdr::LEN;
    let wg_ptr = udp_ptr + UdpHdr::LEN;
    let ip4: Ipv4Hdr = unsafe { read_unchecked(ip4_ptr) };
    let udp: UdpHdr = unsafe { read_unchecked(udp_ptr) };

    let saddr: Ipv4Addr = u32::to_be(ip4.src_addr).into();
    let daddr: Ipv4Addr = u32::to_be(ip4.dst_addr).into();
    let sport: u16 = u16::to_be(udp.source).into();
    let dport: u16 = u16::to_be(udp.dest).into();

    // 51820
    warn!(
        "[APP] ===> [[{}]] RX-1: {}:{} -> {}:{} ",
        desc.addr, saddr, sport, daddr, dport,
    );
}
