use anyhow::Result;
use clap::Parser;
use clap_derive::Parser;
use cli_log::*;
use std::net::SocketAddr;
use tokio::{signal::ctrl_c, task::JoinSet};
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long)]
    server: SocketAddr,

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

    let args = Args::parse();
    let tun_name = args.tun_name;
    let port = args.port;
    let server = args.server;

    let mut task_set = JoinSet::new();
    task_set.spawn(client::run(tun_name, port, server, token));

    loop {
        tokio::select! {
            _ = ctrl_c() => {
                token_clone.cancel();
                break;
            },
            Some(res) = task_set.join_next() => {
                match res {
                    Ok(t) if t.is_err() => {
                        error!("client ended with error: {t:?}");
                    },
                    Ok(t) if t.is_ok() => {
                        info!("client finished");
                    },
                    Err(e) => {
                        error!("main client join falied: {e}");
                    }
                    _ => {},
                }
            },
        }
    }

    task_set.join_all().await;
    Ok(())
}
