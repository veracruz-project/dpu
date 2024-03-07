//! Provision and execute parsec.

use anyhow::{anyhow, Result};
use log::{error, info};
use transport::{messages::{Request, Response, Status}, session::{EncryptionMode, Session}};

use std::fs;
use std::fs::File;
use std::io::Read;

const DPU_SERVER_URL: &str = "127.0.0.1:6666";
const PARSEC_APP_NAME: &str = "/tmp/dpu/parsec_app";
const PARSEC_PERM_CMD: &str = "chmod +x /tmp/dpu/parsec_app";
const PARSEC_EXECUTE_CMD: &str = "PARSEC_SERVICE_CONN_TYPE=tcp PARSEC_SERVICE_CONN_IP_ADDR=172.28.97.222  PARSEC_SERVICE_CONN_PORT_NO=8002 /tmp/dpu/parsec_app ping";

// Read program file
fn get_file_data(filename: &String) -> anyhow::Result<Vec<u8>> {

    let mut file = File::open(&filename).unwrap();
    let metadata = fs::metadata(&filename).unwrap();
    let mut file_content = vec![0; metadata.len() as usize];
    file.read(&mut file_content).unwrap();

    Ok(file_content)
}

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

    info!("Preparing parsec-tool executable data...");
    let filename = PARSEC_APP_NAME.to_owned();
    let data = get_file_data(&filename).unwrap();

    info!("Provisioning parsec-tool to DPU...");
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

    info!("Requesting permission change...");
    Session::send_message(dpu_session_id, &Request::Execute(PARSEC_PERM_CMD.to_owned(), None))
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

    info!("Requesting parsec-tool execution..");
    Session::send_message(dpu_session_id, &Request::Execute(PARSEC_EXECUTE_CMD.to_owned(), None))
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
