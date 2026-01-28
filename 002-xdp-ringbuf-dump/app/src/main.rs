mod bpf_helper;
mod cli;
mod logger;
mod utils;

use crate::utils::init_with_single_xdp;
use aya::maps::RingBuf;
use log::info;
use pcap_file_tokio::pcap::{PcapPacket, PcapWriter};
use std::{
    ptr, slice,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::File,
    io::{unix::AsyncFd, AsyncWriteExt, BufWriter},
    signal,
    sync::watch,
};

const BEE: &str = "poc_xdp_ring";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    logger::init();
    let args = cli::parse();

    let mut ebpf = init_with_single_xdp(BEE, &args.iface)?;

    let ring_dump = RingBuf::try_from(ebpf.take_map("RING_BUF").unwrap()).unwrap();
    let file_out = File::create(args.out.as_str())
        .await
        .expect("Error creating file out");

    // BufWriter to avoid a syscall per write. BufWriter will manage that for us and reduce the amound of syscalls.
    let stream = BufWriter::with_capacity(8192, file_out);
    let mut pcap_writer = PcapWriter::new(stream).await.expect("Error writing file");

    // Create a channel to signal task termination
    let (tx, rx) = watch::channel(false);

    let pcapdump_task = tokio::spawn(async move {
        let mut rx = rx.clone();
        let mut async_fd = AsyncFd::new(ring_dump).unwrap();

        loop {
            tokio::select! {
                _ = async_fd.readable_mut() => {
                    // wait till it is ready to read and read
                    let mut guard = async_fd.readable_mut().await.unwrap();
                    let rb = guard.get_inner_mut();

                    while let Some(read) = rb.next() {
                        let ptr = read.as_ptr();

                        // retrieve packet len first then packet data
                        let size = unsafe { ptr::read_unaligned::<u16>(ptr as *const u16) };
                        let data = unsafe { slice::from_raw_parts(ptr.byte_add(2), size.into()) };

                        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

                        let packet = PcapPacket::new(ts, size as u32, data);
                        pcap_writer.write_packet(&packet).await.unwrap();
                    }

                    guard.clear_ready();
                },
                _ = rx.changed() => {
                    if *rx.borrow() {
                        break;
                    }
                }
            }
        }

        // End of program, flush the buffer
        let mut buf_writer = pcap_writer.into_writer();
        buf_writer.flush().await.unwrap();
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    // Signal the task to stop
    tx.send(true).unwrap();

    // wait for the task to finish
    pcapdump_task.await.unwrap();

    info!("Exiting...");

    Ok(())
}
