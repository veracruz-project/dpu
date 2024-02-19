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
use log::{debug, error};
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
        let received_msg = Session::receive_message(session_id)?;
        let return_msg = match received_msg {
            // TODO: pass `_attestation_server_url` to Mbed TLS callbacks
            Request::Attest(_attestation_server_url, attester_url) => {
                debug!("dpu_runtime::decode_dispatch Attest");
                match Session::from_url(&attester_url) {
                    Err(e) => {
                        let s = format!("Attestation request failed: {}", e);
                        error!("{}", s);
                        Response::Status(Status::Fail(s))
                    },
                    Ok(final_session_id) => {
                        let s = format!("{}", final_session_id);
                        debug!("Final session ID: {}", s);
                        Response::Status(Status::Success(s))
                    },
                }
            },
            Request::Initialize(_policy, _cert_chain) => {
                debug!("dpu_runtime::decode_dispatch Initialize");
                Response::Status(Status::Success(String::new()))
            },
            Request::UploadFile(filename, data, final_session_id) => {
                debug!("dpu_runtime::decode_dispatch UploadFile");
                match final_session_id {
                    Some(session_id) => {
                        // Upload file on behalf of initiator
                        // TODO: multithread this
                        let msg = Request::UploadFile(filename, data, None);
                        Session::send_message(session_id, msg)?;
                        Session::receive_message(session_id)?
                    },
                    None => {
                        // TODO: Sanitize filename to prevent sender from bypassing the
                        // filesystem's sandbox
                        // TODO: Tear down session sysroot at end of session
                        let session_sysroot = DPURuntime::init_sysroot(session_id)?;
                        let mut path = session_sysroot.clone();
                        path.push(filename);
                        let mut file = File::create(&path)?;
                        file.write_all(&data)?;
                        Response::Status(Status::Success(String::new()))
                    }
                }
            },
            Request::Execute(cmd, final_session_id) => {
                debug!("dpu_runtime::decode_dispatch Execute");
                match final_session_id {
                    Some(session_id) => {
                        // Execute remote command on behalf of initiator
                        // TODO: multithread this
                        let msg = Request::Execute(cmd, None);
                        Session::send_message(session_id, msg)?;
                        Session::receive_message(session_id)?
                    },
                    None => {
                        // Execute shell command in session's sysroot.
                        // Warning: This is very insecure!
                        let session_sysroot = DPURuntime::init_sysroot(session_id)?;
                        debug!("Executing '{:?}'", cmd);
                        let output = Command::new("/usr/bin/sh")
                            .args(["-c"])
                            .args([cmd])
                            .current_dir(session_sysroot)
                            .output()?;
                        let output = format!("{:?}", output);
                        Response::Status(Status::Success(output))
                    }
                }
            },
        };
        Session::send_message(session_id, return_msg)
    }
}