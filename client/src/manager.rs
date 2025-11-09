use anyhow::Result;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub enum ManagerMessages {}

pub async fn run(
    _manager_rx: mpsc::UnboundedReceiver<ManagerMessages>,
    _token: CancellationToken,
) -> Result<()> {
    Ok(())
}
