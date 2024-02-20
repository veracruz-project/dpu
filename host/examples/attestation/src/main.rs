//! An example to attest nodes.

use anyhow::anyhow;
use log::{error, info};
use transport::{messages::{Request, Response, Status}, session::{Session, SessionId}};


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
    Session::send_message_plaintext(
        dpu1_session_id,
        &Request::Attest(
            proxy_attestation_server_url.to_owned(),
            dpu2_server_url.to_owned())
    ).map_err(|e| {
        error!("Failed to send attestation message to DPU1.  Error returned: {:?}.", e);
        e
    })?;
    let response = Session::receive_message_plaintext(dpu1_session_id).map_err(|e| {
        error!("Failed to receive response to attestation message.  Error received: {:?}.", e);
        e
    })?;
    let dpu2_session_id = match response {
        Response::Status(Status::Success(m)) => {
            info!("Successfully attested DPU2: DPU2 session ID = {}", m);
            m.parse::<SessionId>()?
        },
        Response::Status(Status::Fail(e)) => {
            error!("Error attesting DPU2: {}", e);
            return Err(anyhow!("Indirect attestation failure."));
        },
        _ => {
            error!("Error attesting DPU2: Other");
            return Err(anyhow!("Indirect attestation failure."));
        },
    };

    // Now we can send mesasages to DPU2 using `dpu2_session_id`
    info!("Requesting remote execution...");
    Session::send_message_plaintext(dpu1_session_id, &Request::Execute("ls -al".to_owned(), Some(dpu2_session_id)))
        .map_err(|e| {
            error!("Failed to send execution message to DPU2.  Error returned: {:?}.", e);
            e
        })?;
    let response = Session::receive_message_plaintext(dpu1_session_id).map_err(|e| {
        error!("Failed to receive response to execution message.  Error received: {:?}.", e);
        e
    })?;
    match response {
        Response::Status(Status::Success(output)) => {
            info!("Successfully executed code remotely. Output: \n{}", output);
        },
        Response::Status(Status::Fail(e)) => {
            error!("Error executing code remotely: {}", e);
            return Err(anyhow!("Remote execution failure."));
        },
        _ => {
            error!("Error executing code remotely: Other");
            return Err(anyhow!("Remote execution failure."));
        },
    }

    Ok(())
}