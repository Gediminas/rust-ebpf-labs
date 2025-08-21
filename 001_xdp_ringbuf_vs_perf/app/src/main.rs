#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

mod logger;
mod utils;

use anyhow::Context as _;
use aya::{
    maps::{perf::AsyncPerfEventArray, MapData, PerCpuArray, RingBuf},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use clap::Parser;
use core::slice;
use log::{debug, error, info, warn};
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use poc_common::{PerfEvent, RingEvent, Stat};
use std::{
    mem::{self, offset_of},
    net::Ipv4Addr,
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

const PERF_BUF_COUNT: usize = 100;
const PERF_BUF_SIZE: usize = 9000;

static EXIT_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));
static RECV_PACKETS: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));
static LOST_PACKETS: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));
static IDLE_CYCLES: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));
static LATENCY_SUM: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long, default_value = None)]
    pub timeout: Option<u64>,

    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(short, long, default_value = "false")]
    perf: bool,

    #[clap(short, long, default_value = "false")]
    ring: bool,

    #[clap(long, default_value = None)]
    pub ring_delay: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    logger::init();

    let (mode, bee) = if args.ring {
        if args.ring_delay.is_some() {
            ("RING", "poc_ring_with_delay")
        } else {
            ("RING", "poc_ring_with_epoll")
        }
    } else if args.perf {
        ("PERF", "poc_perf")
    } else {
        ("NONE", "poc_none")
    };

    let mut ebpf = init_bpf(&args.iface, bee)?;

    let stat: PerCpuArray<MapData, Stat> =
        PerCpuArray::try_from(ebpf.take_map("STAT").expect("STAT-1")).expect("STAT-2");

    // Moved here out of timer scope
    let ring = RingBuf::try_from(ebpf.take_map("RING").expect("RING")).expect("RING-2");

    // Moved here out of timer scope
    let (poll, events) = {
        let fd = ring.as_raw_fd();
        let mut source = SourceFd(&fd);
        let poll = Poll::new().expect("E203");
        let events = Events::with_capacity(8);

        poll.registry()
            .register(&mut source, Token(0), Interest::READABLE)
            .expect("E208");
        (poll, events)
    };

    let start_time = utils::now_ns();
    let start_cpu_time = utils::cpu_time_ms();

    if args.ring {
        spawn_ringbuf_loop(&mut ebpf, args.ring_delay, &stat, ring, poll, events)?;
    } else if args.perf {
        spawn_perf_loop(&mut ebpf)?;
    } else {
        warn!("NONE: base-line"); // no perf, no ringbuf
    }

    // wait for the end
    if let Some(millis) = args.timeout {
        debug!("Waiting {} ms", millis);
        time::sleep(tokio::time::Duration::from_millis(millis)).await;
    } else {
        debug!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
    }

    EXIT_FLAG.store(true, Relaxed);

    let end_cpu_time = utils::cpu_time_ms();
    let end_time = utils::now_ns();

    let elapsed = (end_time - start_time) as f64 / 1_000_000_000.0;
    let sys_ms = (end_cpu_time.0 - start_cpu_time.0) as f64 / 1_000.0 / elapsed;
    let usr_ms = (end_cpu_time.1 - start_cpu_time.1) as f64 / 1_000.0 / elapsed;

    let stat = stat.get(&0, 0)?;
    let total_packets = stat.iter().fold(0, |acc, x| acc + x.total_packets);

    print_report(&args, total_packets, elapsed, sys_ms, usr_ms);
    Ok(())
}

#[inline(always)]
fn process_packet_burst(ring: &mut RingBuf<MapData>) {
    // let mut burst = 0;
    while let Some(item) = ring.next() {
        let ptr = item.as_ptr();
        let evt = unsafe { ptr::read_unaligned(ptr as *const RingEvent) };
        let now = utils::now_ns();
        let latency = now - evt.time;

        debug!("{:?}", &evt.buf[..evt.len]);

        RECV_PACKETS.fetch_add(1, Relaxed);
        LATENCY_SUM.fetch_add(latency as usize, Relaxed);
        // burst += 1;
    }
    // if burst > 1 {
    //     error!("BURST: {burst}");
    // }

    IDLE_CYCLES.fetch_add(1, Relaxed);
}

fn spawn_ringbuf_loop(
    ebpf: &mut Ebpf,
    ring_delay: Option<u32>,
    stat: &PerCpuArray<MapData, Stat>,
    mut ring: RingBuf<MapData>,
    mut poll: Poll,
    mut events: Events,
) -> anyhow::Result<()> {
    std::thread::spawn(move || match ring_delay {
        Some(delay) => {
            warn!("RING: Userspace loop delay: {delay}");

            while !EXIT_FLAG.load(Relaxed) {
                process_packet_burst(&mut ring);

                if delay > 0 {
                    std::thread::sleep(Duration::from_micros(delay as u64));
                }
            }
        }
        None => {
            warn!("RING: Userspace loop with epoll");

            while !EXIT_FLAG.load(Relaxed) {
                process_packet_burst(&mut ring);

                poll.poll(&mut events, Some(Duration::from_millis(100)))
                    .expect("E213");
            }
        }
    });

    let stat = stat.get(&0, 0)?;
    let lost = stat.iter().fold(0, |acc, x| acc + x.ring_lost_packets);
    LOST_PACKETS.store(lost, Relaxed);

    Ok(())
}

fn spawn_perf_loop(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let cpus = online_cpus().expect("CPU");
    let num_cpus = cpus.len();

    warn!("PERF: Userspace listeners: {num_cpus} (CPUs)");

    let mut events =
        AsyncPerfEventArray::try_from(ebpf.take_map("PERF").expect("PERF")).expect("PERF-2");

    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        let recv = RECV_PACKETS.clone();
        let lost = LOST_PACKETS.clone();

        tokio::task::spawn(async move {
            let mut buffers = (0..PERF_BUF_COUNT)
                .map(|_| BytesMut::with_capacity(PERF_BUF_SIZE))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.expect("E7732");
                lost.fetch_add(events.lost, Relaxed);
                recv.fetch_add(events.read, Relaxed);

                for rcv_buf in buffers.iter_mut().take(events.read) {
                    let data: PerfEvent =
                        unsafe { ptr::read_unaligned(rcv_buf.as_ptr() as *const PerfEvent) };

                    let latency = utils::now_ns() - data.time;
                    LATENCY_SUM.fetch_add(latency as usize, Relaxed);

                    let pos = mem::size_of::<PerfEvent>();
                    let pkt_buf = rcv_buf.split().freeze().slice(pos..pos + data.len);

                    let ethhdr = pkt_buf.slice(..EthHdr::LEN);
                    let ethhdr = unsafe { ptr::read_unaligned(ethhdr.as_ptr() as *const EthHdr) };
                    let ethty = ethhdr.ether_type; // EthHdr struct is packed -> requires local copy
                    assert!(ethty == EtherType::Ipv4);

                    let pos = EthHdr::LEN;
                    let ip4 = pkt_buf.slice(pos..pos + Ipv4Hdr::LEN);
                    let ip4 = unsafe { ptr::read_unaligned(ip4.as_ptr() as *const Ipv4Hdr) };
                    assert!(ip4.proto == IpProto::Udp);

                    let pos = EthHdr::LEN + Ipv4Hdr::LEN;
                    let udp = pkt_buf.slice(pos..pos + UdpHdr::LEN);
                    let udp = unsafe { ptr::read_unaligned(udp.as_ptr() as *const UdpHdr) };

                    let saddr = Ipv4Addr::from(u32::from_be(ip4.src_addr));
                    let daddr = Ipv4Addr::from(u32::from_be(ip4.dst_addr));
                    let sport = u16::from_be(udp.source);
                    let dport = u16::from_be(udp.dest);

                    let len = data.len;
                    let lat = latency / 1000;
                    debug!("APP: {lat:3} us / {saddr:?}:{sport} -> {daddr:?}:{dport} / {len} b");
                }
            }
        });
    }

    Ok(())
}

fn init_bpf(iface: &str, bee: &str) -> anyhow::Result<Ebpf> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/poc"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut Xdp = ebpf.program_mut(bee).unwrap().try_into()?;
    program.load()?;
    program.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    debug!("eBPF loaded: {bee}");
    Ok(ebpf)
}

fn print_report(args: &Args, total_packets: usize, elapsed: f64, sys_ms: f64, usr_ms: f64) {
    if !args.perf && !args.ring {
        RECV_PACKETS.store(total_packets, Relaxed);
    }

    let recv_packets = RECV_PACKETS.load(Relaxed);
    let idle_cycles = IDLE_CYCLES.load(Relaxed);
    let latency_sum = LATENCY_SUM.load(Relaxed);
    let lost_packets = LOST_PACKETS.load(Relaxed);

    let latency_micro = latency_sum as f64 / recv_packets as f64 / 1000.0;
    let pps = recv_packets as f64 / elapsed;

    if latency_sum == 0 {
        info!("* Latency:    {latency_micro:9.0} µs/pk");
    } else {
        warn!("* Latency:    {latency_micro:9.0} µs/pk");
    }

    if recv_packets == 0 {
        error!("* Throughput: {pps:9.0} pk/s  ({recv_packets} pk /  {elapsed:.3} s)");
    } else if recv_packets > 10000 {
        let pps = pps / 1000.0;
        warn!("* Throughput: {pps:9.0} kpk/s  ({recv_packets:.0} pk / {elapsed:.3} s)");
    } else {
        warn!("* Throughput: {pps:9.0} pk/s  ({recv_packets} pk /  {elapsed:.3} s)");
    }

    if lost_packets == 0 {
        info!("* Lost:       {lost_packets:9} pk");
    } else {
        let lost_percent = 100.0 * LOST_PACKETS.load(Relaxed) as f64 / total_packets as f64;
        error!("* Lost:       {lost_percent:9.6} pk%  ({lost_packets:9} pk)");
    }

    info!("* Idle:       {idle_cycles:9} cycles");

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
}
