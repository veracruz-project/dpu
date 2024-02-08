//! Manage transport session.

use crate::tls;
#[cfg(feature = "initiator")]
use crate::tls_server;
#[cfg(feature = "responder")]
use crate::tls_client;
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use log::info;
use mbedtls::ssl::Context;
use mbedtls_sys::psa::key_handle_t;
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, net::TcpStream, sync::{Mutex, atomic::{AtomicU32, Ordering}, Arc}};

////////////////////////////////////////////////////////////////////////////////
// Various bits of persistent state.
////////////////////////////////////////////////////////////////////////////////
lazy_static! {
    /// Hashmap of session IDs (handles) mapped to sessions
    /// TODO: Remove expired sessions from hashmap
    /// XXX: Do we really need a session ID?
    static ref SESSIONS: Mutex<HashMap<SessionId, Session>> =
        Mutex::new(HashMap::new());
    static ref SESSION_COUNTER: AtomicU32 = AtomicU32::new(0);
}

pub type SessionId = u32;

#[cfg(feature = "responder")]
#[allow(dead_code)]
pub struct ResponderContext {
    key_handle: key_handle_t,
    client_attestation_type_list: [u16; 3],
}

/// Session
pub struct Session {
    /// TLS session. Exposes a transparent I/O abstraction that simplifies the use of TLS: just read/write from/to it
    tls_context: Context<TcpStream>,
    /// Additional context for miscellaneous responder-side data that must live through the entire session
    #[cfg(feature = "responder")]
    #[allow(dead_code)]
    responder_context: Option<ResponderContext>,
}

impl Session {
    /// Create session from responder's URL. Used by the initiator to attest the responder and establish a secure channel with the responder.
    /// A few notes on the implementation of attested TLS (https://github.com/CCC-Attestation/attested-tls-po) used here:
    ///   - The TLS client is the attester (responder here) and the TLS server is the relying party (initiator here)
    ///   - It only implements the background check attestation model
    ///   - Mutual attestation is not supported
    #[cfg(feature = "initiator")]
    pub fn from_url(responder_url: &str) -> Result<SessionId> {
        // Connect to responder
        let socket = TcpStream::connect(responder_url)
            .map_err(|e| anyhow!("Could not connect to responder on {}: {}", responder_url, e))?;
        info!("Connected to responder on {}.", responder_url);

        info!("Initializing Veraison session...");
        tls_server::init_veraison_session("http://vfe:8080", 8);

        info!("Establishing TLS server context...");
        let config = tls_server::generate_tls_server_config()?;
        let mut tls_context = Context::new(Arc::new(config));
        tls_context.establish(socket, None)?;
        info!("TLS server context established");

        // Add session to hashmap
        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .map_err(|_| anyhow!("Could not lock session hash table"))?
            .insert(
                session_id,
                Self {
                    tls_context,
                    responder_context: None
                }
            );
        info!("Session added to hashmap");

        Ok(session_id)
    }

    /// Create session from socket. Used by the responder to get attested and establish a secure channel with the initiator. Cf. `Session::from_url()` for more details
    #[cfg(feature = "responder")]
    pub fn from_socket(socket: TcpStream) -> Result<SessionId> {
        // Establish TLS client context
        info!("Establishing TLS client context...");
        let (config, key_handle, client_attestation_type_list) = tls_client::generate_tls_client_config()?;
        let mut tls_context = Context::new(Arc::new(config));
        tls_context.establish(socket, None)?;
        info!("TLS client context established");

        // Add session to hashmap
        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .map_err(|_| anyhow!("Could not lock session hash table"))?
            .insert(
                session_id,
                Self {
                    tls_context,
                    responder_context: Some(ResponderContext {
                        key_handle: *key_handle,
                        client_attestation_type_list: *client_attestation_type_list,
                    })
                }
            );

        Ok(session_id)
    }

    pub fn send_message<T>(session_id: SessionId, data: T) -> Result<()>
    where
    T: Serialize,
    {
        let mut s = SESSIONS
            .lock()
            .map_err(|_| anyhow!("Could not lock session hash table"))?;
        let s = s
            .get_mut(&session_id)
            .ok_or(anyhow!("Session does not exist"))?;
        tls::send_message(&mut s.tls_context, data)
    }

    pub fn receive_message<T>(session_id: SessionId) -> Result<T>
    where
    T: DeserializeOwned,
    {
        let mut s = SESSIONS
            .lock()
            .map_err(|_| anyhow!("Could not lock session hash table"))?;
        let s = s
            .get_mut(&session_id)
            .ok_or(anyhow!("Session does not exist"))?;
        tls::receive_message(&mut s.tls_context)
    }
}