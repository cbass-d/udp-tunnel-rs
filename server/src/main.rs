use anyhow::Result;
use clap::Parser;
use clap_derive::Parser;
use cli_log::*;
use std::net::Ipv4Addr;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long)]
    address: Ipv4Addr,

    #[arg(short, long)]
    tun_name: Option<String>,

    #[arg(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_cli_log!();

    let token = CancellationToken::new();
    let token_clone = token.clone();
    let ctrlc = ctrlc2::AsyncCtrlC::new(move || {
        token_clone.cancel();
        true
    })?;

    let args = Args::parse();
    let tun_name = args.tun_name;
    let address = args.address;
    let port = args.port;

    println!("[*] Starting server...");
    server::start(token, tun_name, address, port).await?;

    ctrlc.await?;
    Ok(())
}
