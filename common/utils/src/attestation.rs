//! An attestation helper.
//! Currently only supports PSA attestation.

use anyhow::{anyhow, Result};
use getrandom::getrandom;
use log::{error, info};
use mbedtls::hash::{Md, Type};
use nix::libc::c_char;
use proxy_attestation_client;
use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key, psa_initial_attest_remove_key,
};
use transport::{messages::{Request, Response, Status}, session::{Session, SessionId}};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// **TOTALLY INSECURE** root private key to use for PSA attestation.
///
/// NOTE that attestation is "mocked up" and totally insecure.  See the
/// attestation flow for AWS Nitro Enclaves for a secure attestation
/// implementation.  This is merely here for illustrative purposes.
static TOTALLY_INSECURE_ROOT_PRIVATE_KEY: [u8; 32] = [
    0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
    0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76, 0xa1, 0x44,
];

// Yes, I'm doing what you think I'm doing here. Each instance of the SGX root enclave
// will have the same public key. Yes, I'm embedding that key in the source
// code. I could come up with a complicated system for auto generating a key
// for each instance, and then use that key.
// That's what needs to be done if you want to productize this.
// That's not what I'm going to do for this research project
static TOTALLY_INSECURE_ROOT_PUBLIC_KEY: [u8; 65] = [
    0x4, 0x5f, 0x5, 0x5d, 0x39, 0xd9, 0xad, 0x60, 0x89, 0xf1, 0x33, 0x7e, 0x6c, 0xf9, 0x57, 0xe,
    0x6f, 0x84, 0x25, 0x5f, 0x16, 0xf8, 0xcd, 0x9c, 0xe4, 0xa0, 0xa2, 0x8d, 0x7a, 0x4f, 0xb7, 0xe4,
    0xd3, 0x60, 0x37, 0x2a, 0x81, 0x4f, 0x7, 0xc2, 0x5a, 0x24, 0x85, 0xbf, 0x47, 0xbc, 0x84, 0x47,
    0x40, 0xc5, 0x9b, 0xff, 0xff, 0xd2, 0x76, 0x32, 0x82, 0x4d, 0x76, 0x4d, 0xb4, 0x50, 0xee, 0x9f,
    0x22,
];

/// Compute SHA-256 hash/digest.
fn sha256(x: &[u8]) -> Vec<u8> {
    const HASH_SIZE: usize = 32;
    let mut out: [u8; HASH_SIZE] = [0; HASH_SIZE];
    let n = Md::hash(Type::Sha256, x, &mut out);
    if n.is_err() || n.unwrap() != HASH_SIZE {
        panic!("bad sha256")
    }
    out.to_vec()
}

fn generate_csr(private_key: &[u8]) -> Result<Vec<u8>> {
    let mut rng = |buffer: *mut u8, size: usize| {
        let mut slice = unsafe { std::slice::from_raw_parts_mut(buffer, size) };
        let _ = getrandom(&mut slice);
        0
    };
    let mut pk_private = mbedtls::pk::Pk::from_private_key(&mut rng, private_key, None)?;
    let csr = mbedtls::x509::csr::Builder::new()
        .key(&mut pk_private)
        .subject("C=US")
        .unwrap()
        .subject("ST=Texas")
        .unwrap()
        .subject("L=Austin")
        .unwrap()
        .subject("O=Veracruz")
        .unwrap()
        .subject("OU=Compute Enclave")
        .unwrap()
        .subject("CN=VeracruzCompute")
        .unwrap()
        .signature_hash(mbedtls::hash::Type::Sha256)
        .write_der_vec(&mut rng)
        .unwrap();
    Ok(csr)
}

/// Request attestation.
pub fn request_attestation(session_id: SessionId, attestation_server_url: &str) -> anyhow::Result<()> {
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

    // Send a message to the attester (i.e. the party producing the evidence)
    Session::send_message(session_id, &Request::Attestation(challenge, challenge_id)).map_err(|e| {
        error!("Failed to send attestation message to attester.  Error returned: {:?}.", e);
        e
    })?;

    info!("Attestation message successfully sent to attester.");

    let received: Response = Session::receive_message(session_id).map_err(|e| {
        error!("Failed to receive response to attestation message.  Error received: {:?}.", e);
        e
    })?;

    info!("Response to attestation message received from attester.");

    let (token, csr) = match received {
        Response::AttestationData(token, csr) => {
            (token, csr)
        }
        otherwise => {
            error!(
                "Unexpected response received from attester: {:?}.",
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

    info!("Certificate chain received from attestation server.  Forwarding to attester.");

    let policy = "";
    Session::send_message(session_id, &Request::Initialize(policy.to_owned(), cert_chain)).map_err(|e| {
        error!("Failed to send certificate chain message to attester.  Error returned: {:?}.", e);
        e
    })?;

    info!("Certificate chain message sent, awaiting response.");

    let received: Response = Session::receive_message(session_id).map_err(|e| {
        error!("Failed to receive response to certificate chain message message from attester.  Error returned: {:?}.", e);
        e
    })?;

    match received {
        Response::Status(Status::Success(m)) => {
            info!("Received success message from runtime manager enclave: '{}'", m);
            Ok(())
        },
        Response::Status(otherwise) => {
            Err(anyhow!("Received non-success error code from attester: {:?}.",
            otherwise))
        }
        otherwise => {
            Err(anyhow!("Received unexpected response from attester: {:?}.",
            otherwise))
        }
    }.map_err(|e| { anyhow!("Attestation failed: {}. Aborting.", e) })?;

    Ok(())
}

/// Generate atestation data. Called by the attester upon receiving an attestation request from the attester.
/// Performs a dummy implementation of native attestation using the insecure
/// root private keys and computing the runtime manager hash.  If successful,
/// produces a PSA attestation token binding the CSR hash, runtime manager hash,
/// and challenge.
pub fn generate_attestation_data(measurement: &Vec<u8>, challenge: &Vec<u8>, private_key: &[u8]) -> Result<Response> {
    let csr = generate_csr(private_key).map_err(|e| {
        error!(
            "Failed to generate certificate signing request.  Error produced: {:?}.",
            e
        );

        e
    })?;

    let csr_hash = sha256(&csr);

    let mut root_key_handle: u32 = 0;

    let ret = unsafe {
        psa_initial_attest_load_key(
            TOTALLY_INSECURE_ROOT_PRIVATE_KEY.as_ptr(),
            TOTALLY_INSECURE_ROOT_PRIVATE_KEY.len(),
            &mut root_key_handle,
        )
    };

    if 0 != ret {
        return Err(anyhow!(
            format!("unsafe call error: psa_initial_attest_load_key ({})",
            ret as u32,
        )));
    }

    let mut token = Vec::with_capacity(2048);
    let mut token_len: usize = 0;

    // Section 3.2.1 of https://www.ietf.org/archive/id/draft-tschofenig-rats-psa-token-09.txt
    // EAT UEID of type RAND.
    // Length must be 33 bytes
    // first byte MUST be 0x01 (RAND)
    // next 32 bytes must be the hash of the key (Is this the public or private key? It's unclear, presume the public key because a hash of the private key could theoretically bleed info
    // about the private key)
    let public_key_hash = sha256(&TOTALLY_INSECURE_ROOT_PUBLIC_KEY);
    let mut enclave_name: Vec<u8> = Vec::new();
    enclave_name.push(0x01);
    enclave_name.extend_from_slice(&public_key_hash);


    let ret = unsafe {
        psa_initial_attest_get_token(
            measurement.as_ptr(),
            measurement.len(),
            csr_hash.as_ptr() as *const u8,
            csr_hash.len(),
            enclave_name.as_ptr() as *const c_char,
            enclave_name.len(),
            challenge.as_ptr() as *const u8,
            challenge.len(),
            token.as_mut_ptr() as *mut u8,
            token.capacity(),
            &mut token_len,
        )
    };

    if 0 != ret {
        return Err(anyhow!(
            format!("unsafe call error: psa_initial_attest_get_token ({})",
            ret as u32,
        )));
    }

    unsafe { token.set_len(token_len as usize) };

    let ret = unsafe { psa_initial_attest_remove_key(root_key_handle) };

    if 0 != ret {
        return Err(anyhow!(
            format!("unsafe call error: psa_initial_attest_remove_key ({})",
            ret as u32,
        )));
    }

    return Ok(Response::AttestationData(token, csr));
}
