use aya::{include_bytes_aligned, programs::KProbe, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, LevelFilter};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    info!("Initializing 'q'...");
    let _opt = Opt::parse();
    env_logger::builder()
        .filter(None, LevelFilter::Trace)
        .init();

    // Compile the eBPF probe directly into the binary.
    //
    // The "release" binary is critical here or the symbol offset
    // will return an error! Ensure that you are both building a
    // --release binary for the eBPF probe as well as referencing
    // a release binary for the logger!
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../ebpf/target/bpfel-unknown-none/release/qprobe"
    ))?;
    info!("Success! Loaded eBPF probe into kernel");

    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // =============================================================================================
    // q_tcp_connect -> kprobe__tcp_connect
    //
    //let program: &mut KProbe = bpf.program_mut("q_tcp_connect").unwrap().try_into()?;
    //program.load()?;
    //program.attach("tcp_connect", 0)?;
    //info!(" --> Attached: kprobe__tcp_connect");
    //
    // =============================================================================================

    // =============================================================================================
    // q_tcp_conn_request -> kprobe__tcp_conn_request
    //
    let program: &mut KProbe = bpf.program_mut("q_tcp_conn_request").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_conn_request", 0)?;
    info!(" --> Attached: kprobe__tcp_conn_request");
    //
    // =============================================================================================

    // TODO new kprobe

    info!("q: Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    Ok(())
}
