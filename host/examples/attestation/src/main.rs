//! An example to attest nodes.

use anyhow::anyhow;
use log::{error, info};
use transport::{messages::{Request, Response, Status}, session::Session};


const DPU1_SERVER_URL: &str = "127.0.0.1:6666";
const DPU2_SERVER_URL: &str = "127.0.0.1:6667";
const ATTESTATION_SERVER_URL: &str = "127.0.0.1:3010";

/// Attest DPU1 and DPU2 via DPU1. Abort on failure.
fn main() -> anyhow::Result<()> {
    env_logger::init();

    // TODO: Parse arguments (DPU1, DPU2, attestation server) with clap

    let dpu1_server_url = DPU1_SERVER_URL;
    let dpu2_server_url = DPU2_SERVER_URL;
    let proxy_attestation_server_url = ATTESTATION_SERVER_URL;

    info!("Establishing attested connection with DPU1...");
    let dpu1_session_id = Session::from_url(dpu1_server_url)?;

    info!("Indirectly attesting DPU2 via DPU1...");
    Session::send_message(
        dpu1_session_id,
        &Request::Attest(
            proxy_attestation_server_url.to_owned(),
            dpu2_server_url.to_owned())
    ).map_err(|e| {
        error!("Failed to send attestation message to DPU1.  Error returned: {:?}.", e);
        e
    })?;
    let response = Session::receive_message(dpu1_session_id).map_err(|e| {
        error!("Failed to receive response to attestation message.  Error received: {:?}.", e);
        e
    })?;
    match response {
        Response::Status(Status::Success(_)) => {
            info!("Successfully attested DPU2.");
        },
        _ => {
            error!("Error attesting DPU2.");
            return Err(anyhow!("Indirect attestation failure."));
        },
    }

    Ok(())
}