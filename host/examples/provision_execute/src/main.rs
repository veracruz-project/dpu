//! An example to send a file.

use anyhow::anyhow;
use log::{error, info};
use utils::attestation;
use transport::{messages::{Request, Response, Status}, session::Session};


const DPU_SERVER_URL: &str = "127.0.0.1:6666";
const ATTESTATION_SERVER_URL: &str = "127.0.0.1:3010";

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // TODO: Parse arguments with clap

    let dpu_server_url = DPU_SERVER_URL;
    let proxy_attestation_server_url = ATTESTATION_SERVER_URL;

    let dpu_session_id = Session::from_url(dpu_server_url)?;

    info!("Attesting DPU...");
    attestation::request_attestation(dpu_session_id, proxy_attestation_server_url)?;
    info!("Successfully attested DPU.");

    info!("Preparing provisions...");
    let filename = "foo.txt".to_owned();
    let data = b"bar".to_vec();

    info!("Provisioning DPU...");
    Session::send_message(dpu_session_id, &Request::UploadFile(filename, data))
        .map_err(|e| {
            error!("Failed to send provisioning message to DPU.  Error returned: {:?}.", e);
            e
        })?;
    let response = Session::receive_message(dpu_session_id).map_err(|e| {
        error!("Failed to receive response to provisioning message.  Error received: {:?}.", e);
        e
    })?;
    match response {
        Response::Status(Status::Success(_)) => {
            info!("Successfully provisioned DPU.");
        },
        _ => {
            error!("Error provisioning DPU.");
            return Err(anyhow!("Provisioning failure."));
        },
    }

    info!("Requesting remote execution...");
    Session::send_message(dpu_session_id, &Request::Execute("cat foo.txt".to_owned()))
        .map_err(|e| {
            error!("Failed to send execution message to DPU.  Error returned: {:?}.", e);
            e
        })?;
    let response = Session::receive_message(dpu_session_id).map_err(|e| {
        error!("Failed to receive response to execution message.  Error received: {:?}.", e);
        e
    })?;
    match response {
        Response::Status(Status::Success(output)) => {
            info!("Successfully executed code remotely. Output: \n{}", output);
        },
        _ => {
            error!("Error executing code remotely.");
            return Err(anyhow!("Remote execution failure."));
        },
    }

    Ok(())
}