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
use log::debug;
use std::{fs::{File, create_dir_all}, io::Write, path::PathBuf, process::Command};
use transport::{messages::{Request, Response, Status}, session::{Session, SessionId}};

/// Filesystem root. Session sysroots are derived from it.
/// Warning: This is insecure and should be better sandboxed.
const FILESYSTEM_ROOT: &'static str = "/tmp/dpu_rm";

pub struct SessionContext {
}

impl SessionContext {
    fn new() -> Result<Self> {
        Ok(Self {})
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

    pub fn init_sysroot(session_id: SessionId) -> Result<PathBuf> {
        let mut session_sysroot = PathBuf::from(FILESYSTEM_ROOT);
        session_sysroot.push(session_id.to_string());
        create_dir_all(&session_sysroot)?;
        Ok(session_sysroot)
    }

    /// Process host's messages here.
    /// Note that there is no state machine specifying the order in which
    /// messages should be received.
    pub fn decode_dispatch(&self, session_id: SessionId) -> Result<()> {
        let received_message = Session::receive_message(session_id)?;
        let return_message = match received_message {
            Request::Attestation(challenge, _challenge_id) => {
                /*debug!("dpu_runtime::decode_dispatch Attestation");
                let ret = self.attestation(&challenge)?;
                trace!(
                    "dpu_runtime::decode_dispatch Attestation complete with ret:{:?}\n",
                    ret
                );
                ret*/
                todo!()
            },
            Request::IndirectAttestation(attestation_server_url, attester_url) => {
                debug!("dpu_runtime::decode_dispatch IndirectAttestation");
                match Session::from_url(&attester_url) {
                    Err(e) => {
                        Response::Status(Status::Fail(
                            format!("IndirectAttestation request failed: {}", e)
                        ))
                    },
                    Ok(session_id) => {
                        Response::Status(Status::Success(format!("Session {} established", session_id)))
                        /*match attestation::request_attestation(session_id, &attestation_server_url) {
                            Ok(_) => Response::Status(Status::Success(String::new())),
                            Err(e) => Response::Status(Status::Fail(
                                format!("IndirectAttestation request failed: {}", e)
                            )),
                        }*/
                    },
                }
            },
            Request::Initialize(_policy, _cert_chain) => {
                debug!("dpu_runtime::decode_dispatch Initialize");
                Response::Status(Status::Success(String::new()))
            },
            Request::UploadFile(filename, data) => {
                debug!("dpu_runtime::decode_dispatch UploadFile");
                // TODO: Sanitize filename to prevent sender from bypassing the
                // filesystem's sandbox
                // TODO: Tear down session sysroot at end of session
                let session_sysroot = DPURuntime::init_sysroot(session_id)?;
                let mut path = session_sysroot.clone();
                path.push(filename);
                let mut file = File::create(&path)?;
                file.write_all(&data)?;
                Response::Status(Status::Success(String::new()))
            },
            Request::Execute(cmd) => {
                // Execute shell command from the session's sysroot.
                // Warning: This is insecure.
                let session_sysroot = DPURuntime::init_sysroot(session_id)?;
                debug!("dpu_runtime::decode_dispatch Execute");
                debug!("Executing '{:?}'", cmd);
                let output = Command::new("/usr/bin/sh")
                    .args(["-c"])
                    .args([cmd])
                    .current_dir(session_sysroot)
                    .output()?;
                let output = format!("{:?}", output);
                Response::Status(Status::Success(output))
            },
        };
        Session::send_message(session_id, return_message)
    }
}

/*
pub trait PlatformRuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<Response>;
}

impl PlatformRuntime for DPURuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<Response> {
        let rmm = crate::RUNTIME_MANAGER_MEASUREMENT.lock().unwrap();
        attestation::generate_attestation_data(&rmm, challenge, &self.session_context.private_key())
    }
}
*/