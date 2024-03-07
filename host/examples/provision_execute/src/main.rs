//! An example to send a file.

use anyhow::{anyhow, Result};
use log::{error, info};
use transport::{messages::{Request, Response, Status}, session::{EncryptionMode, Session}};

const DPU_SERVER_URL: &str = "127.0.0.1:6666";

fn main() -> Result<()> {
    env_logger::init();

    // TODO: Parse arguments with clap

    let dpu_server_url = DPU_SERVER_URL;

    info!("Establishing attested connection with DPU...");
    let dpu_session_id = Session::from_url(dpu_server_url)?;

    info!("Downgrading channel to plaintext...");
    Session::send_message(
        dpu_session_id,
        &Request::SetEncryptionMode(EncryptionMode::Plaintext)
    )?;
    Session::set_encryption_mode(dpu_session_id, EncryptionMode::Plaintext)?;
    let response = Session::receive_message(dpu_session_id)?;
    match response {
        Response::Status(Status::Success(_)) => {
            info!("Successfully downgraded channel");
        },
        Response::Status(Status::Fail(e)) => {
            return Err(anyhow!("Error downgrading channel: {}", e));
        },
        _ => {
            return Err(anyhow!("Error downgrading channel: Other"));
        },
    };

    info!("Preparing provisions...");
    let filename = "foo.txt".to_owned();
    let data = b"bar".to_vec();

    info!("Provisioning DPU...");
    Session::send_message(dpu_session_id, &Request::UploadFile(filename, data, None))
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
    Session::send_message(dpu_session_id, &Request::Execute("cat foo.txt".to_owned(), None))
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