use aya::{include_bytes_aligned, programs::KProbe, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();
    env_logger::init();

    // Compile the eBPF probe directly into the binary
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../ebpf/target/bpfel-unknown-none/debug/qprobe"
    ))?;
    println!("q...");

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut KProbe = bpf.program_mut("ebpf").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
