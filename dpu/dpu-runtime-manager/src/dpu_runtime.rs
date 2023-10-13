//! The DPU-specific runtime struct
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::Result;
use getrandom::getrandom;
use log::debug;
use mbedtls;
use std::net::TcpStream;
use transport::{messages::{Request, Response, Status}, session::Session, tcp::{receive_message, send_message}};
use utils::attestation;

pub struct SessionContext {
    /// The private key used by the server (as a Vec<u8> for convenience)
    server_private_key: Vec<u8>,
    /// The public key used by the server (as a Vec<u8> for convenience)
    server_public_key: Vec<u8>,
}

impl SessionContext {
    fn new() -> Result<Self> {
        let (server_public_key, server_private_key) = {
            let mut rng = |buffer: *mut u8, size: usize| {
                let mut slice = unsafe { std::slice::from_raw_parts_mut(buffer, size) };
                let _ = getrandom(&mut slice);
                0
            };
            let mut key =
                mbedtls::pk::Pk::generate_ec(&mut rng, mbedtls::pk::EcGroupId::SecP256R1)?;
            (
                key.write_public_der_vec()?[23..].to_vec(),
                key.write_private_der_vec()?,
            )
        };

        Ok(Self {
            server_private_key,
            server_public_key
        })
    }

    /// Returns the public key (as a Vec<u8>) of the server
    #[inline]
    pub fn public_key(&self) -> Vec<u8> {
        return self.server_public_key.clone();
    }

    /// Returns the private key of the server
    /// TODO: Should we do any operations with this key inside this struct instead?
    /// Returning the private key seems a little irresponsible (not that the
    /// software requesting it couldn't just inspect the memory, but still...)
    #[inline]
    pub fn private_key(&self) -> &[u8] {
        &self.server_private_key
    }
}

pub struct DPURuntime {
    pub session_context: SessionContext,
}

impl DPURuntime {
    pub fn new() -> Result<Self> {
        let session_context = SessionContext::new()?;
        Ok(DPURuntime { session_context })
    }

    /// Process host's messages here.
    /// Note that the communication channel between host and DPU is not secure.
    /// Additionally there is no state machine specifying the order in which
    /// messages should be received.
    pub fn decode_dispatch(&self, socket: &mut TcpStream) -> Result<()> {
        let received_message = receive_message(socket)?;
        let return_message = match received_message {
            Request::Attestation(challenge, _challenge_id) => {
                debug!("dpu_runtime::decode_dispatch Attestation");
                let ret = self.attestation(&challenge)?;
                debug!(
                    "dpu_runtime::decode_dispatch Attestation complete with ret:{:?}\n",
                    ret
                );
                ret
            },
            Request::IndirectAttestation(attestation_server_url, attestee_url) => {
                debug!("dpu_runtime::decode_dispatch IndirectAttestation");
                // WIP
                let mut session = Session::new(&attestee_url)?;
                match attestation::request_attestation(session.get_mut_socket(), &attestation_server_url) {
                    Ok(_) => Response::Status(Status::Success),
                    Err(_) => Response::Status(Status::Fail),
                }
            },
            Request::Initialize(_policy, _cert_chain) => {
                debug!("dpu_runtime::decode_dispatch Initialize");
                Response::Status(Status::Success)
            },
        };
        send_message(socket, return_message)
    }
}

pub trait PlatformRuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<Response>;
}

impl PlatformRuntime for DPURuntime {

    fn attestation(&self, challenge: &Vec<u8>) -> Result<Response> {
        let rmm = crate::RUNTIME_MANAGER_MEASUREMENT.lock().unwrap();
        attestation::generate_attestation_data(&rmm, challenge, &self.session_context.private_key())
    }
}
