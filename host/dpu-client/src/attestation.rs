//! An attestation helper.
//! Currently only supports PSA attestation.

use anyhow::anyhow;
use log::{error, info};
use proxy_attestation_client;
use std::net::TcpStream;
use transport::{messages::{Request, Response, Status}, tcp::{receive_message, send_message}};

/// Perform attestation.
pub fn attest(attestation_server_url: &str, attestee_url: &str) -> anyhow::Result<()> {
    info!("Starting attestation.");

    let (challenge_id, challenge) = proxy_attestation_client::start_proxy_attestation(
        attestation_server_url,
    )
        .map_err(|e| {
            anyhow!(
                "Failed to start attestation process.  Error received: {:?}.",
                e
            )
        })?;

    info!("Connecting to attestee.");
    
    let mut socket = TcpStream::connect(&attestee_url).map_err(|e| {
        error!("Could not connect to attestee on {}: {}", attestee_url, e);
        anyhow!(e)
    })?;

    info!("Connected to attestee on {}.", attestee_url);

    // Send a message to the attestee
    send_message(&mut socket, &Request::Attestation(challenge, challenge_id)).map_err(|e| {
        error!("Failed to send attestation message to attestee.  Error returned: {:?}.", e);
        e
    })?;

    info!("Attestation message successfully sent to attestee.");

    let received: Response = receive_message(&mut socket).map_err(|e| {
        error!("Failed to receive response to attestation message.  Error received: {:?}.", e);
        e
    })?;

    info!("Response to attestation message received from attestee.");

    let (token, csr) = match received {
        Response::AttestationData(token, csr) => {
            info!("Response to attestation message successfully received.",);
            (token, csr)
        }
        otherwise => {
            error!(
                "Unexpected response received from attestee: {:?}.",
                otherwise
            );

            return Err(anyhow!("InvalidResponse"));
        }
    };

    info!("Requesting certificate chain from attestation server.");

    let cert_chain = {
        let cert_chain = proxy_attestation_client::complete_proxy_attestation_linux(attestation_server_url, &token, &csr, challenge_id)
            .map_err(|err| {
                error!("proxy_attestation_client::complete_proxy_attestation_linux failed:{:?}", err);
                err
            })?;
        cert_chain
    };

    info!("Certificate chain received from attestation server.  Forwarding to attestee.");

    let policy = "";
    send_message(&mut socket, &Request::Initialize(String::from(policy), cert_chain)).map_err(|e| {
        error!("Failed to send certificate chain message to attestee.  Error returned: {:?}.", e);
        e
    })?;

    info!("Certificate chain message sent, awaiting response.");

    let received: Response = receive_message(&mut socket).map_err(|e| {
        error!("Failed to receive response to certificate chain message message from attestee.  Error returned: {:?}.", e);
        e
    })?;

    match received {
        Response::Status(Status::Success) => {
            info!("Received success message from runtime manager enclave.");
            Ok(())
        },
        Response::Status(otherwise) => {
            Err(anyhow!("Received non-success error code from attestee: {:?}.",
            otherwise))
        }
        otherwise => {
            Err(anyhow!("Received unexpected response from attestee: {:?}.",
            otherwise))
        }
    }.map_err(|e| { anyhow!("Attestation failed: {}. Aborting.", e) })?;

    Ok(())
}
