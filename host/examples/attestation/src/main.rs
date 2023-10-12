//! An example to attest the DPU.

use anyhow::anyhow;
use dpu_client::attestation;
use log::info;

const DPU_SERVER_URL: &str = "127.0.0.1:6666";
const ATTESTATION_SERVER_URL: &str = "127.0.0.1:3010";

/// Attest DPU. Abort on failure.
fn main() -> anyhow::Result<()> {
    env_logger::init();

    let dpu_address = DPU_SERVER_URL;
    let proxy_attestation_server_url = ATTESTATION_SERVER_URL;

    attestation::attest(proxy_attestation_server_url, dpu_address)?;

    info!("Attestation successful.");

    Ok(())
}