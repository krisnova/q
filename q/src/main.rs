use aya::{include_bytes_aligned, programs::KProbe, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();

    env_logger::builder()
        .filter(None, LevelFilter::Trace)
        .init();

    info!("q: Initializing Program...");

    // Compile the eBPF probe directly into the binary
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../ebpf/target/bpfel-unknown-none/release/qprobe"
    ))?;
    info!("Loaded eBPF probe into kernel");

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }
    info!("q: Loading eBPF Programs");
    let program: &mut KProbe = bpf.program_mut("ebpf").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    info!("q: Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
