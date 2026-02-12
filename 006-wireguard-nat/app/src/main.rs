// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

mod cli;

use anyhow::{Context as _, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    programs::{Xdp, XdpFlags},
};
use log::{debug, info, warn};
use tokio::signal;

const BEE: &str = "poc_xdp";

#[tokio::main]
async fn main() -> Result<()> {
    anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    kit::logger::init();
    let args = cli::parse();

    println!("=======================");
    println!("app:        {}", env!("CARGO_CRATE_NAME"));
    println!("bpf:        {}", BEE);
    println!("log-level:  {}", log::max_level());
    println!("iface:      {}", args.iface);
    println!("args:       {:?}", args);
    println!("=======================");

    let mut _ebpf = init_with_single_xdp(BEE, &args.iface)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    info!("Finished");
    Ok(())
}
pub fn init_with_single_xdp(bee: &str, iface: &str) -> Result<Ebpf> {
    kit::system::legacy_memlock_rlimit_remove()?;

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/poc")))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut Xdp = ebpf.program_mut(bee).unwrap().try_into()?;
    program.load()?;
    program.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    debug!("eBPF loaded: {bee}");
    Ok(ebpf)
}
