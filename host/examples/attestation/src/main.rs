//! An example to attest the DPU.

use anyhow::anyhow;
use log::{error, info};
use utils::attestation;
use transport::{messages::{Request, Response, Status}, session::Session, tcp::{receive_message, send_message}};


const DPU1_SERVER_URL: &str = "127.0.0.1:6666";
const DPU2_SERVER_URL: &str = "127.0.0.1:6667";
const ATTESTATION_SERVER_URL: &str = "127.0.0.1:3010";

/// Attest DPU. Abort on failure.
fn main() -> anyhow::Result<()> {
    env_logger::init();

    // TODO: Parse arguments (DPU1, DPU2, attestation server) with clap

    let dpu1_server_url = DPU1_SERVER_URL;
    let dpu2_server_url = DPU2_SERVER_URL;
    let proxy_attestation_server_url = ATTESTATION_SERVER_URL;

    let mut session = Session::new(dpu1_server_url)?;

    info!("Attesting DPU1...");
    attestation::request_attestation(session.get_mut_socket(), proxy_attestation_server_url)?;
    info!("Successfully attested DPU1.");

    info!("Indirectly attesting DPU2...");
    send_message(session.get_mut_socket(), &Request::IndirectAttestation(String::from(proxy_attestation_server_url), String::from(dpu2_server_url))).map_err(|e| {
        error!("Failed to send attestation message to attestee.  Error returned: {:?}.", e);
        e
    })?;
    let response = receive_message(session.get_mut_socket()).map_err(|e| {
        error!("Failed to receive response to attestation message.  Error received: {:?}.", e);
        e
    })?;
    match response {
        Response::Status(Status::Success) => {
            info!("Successfully attested DPU2.");
        },
        _ => {
            info!("Error attesting DPU2.");
            return Err(anyhow!("Attestation failure."));
        },
    }

    Ok(())
}