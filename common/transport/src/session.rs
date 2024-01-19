// Manage transport session.

use crate::tls;
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use log::info;
use mbedtls::{ssl::{Config, Context, Version, config::{Endpoint, Transport, Preset}}, x509::Certificate, pk::Pk};
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, net::TcpStream, sync::{Mutex, atomic::{AtomicU32, Ordering}, Arc}, borrow::Cow};

////////////////////////////////////////////////////////////////////////////////
// Various bits of persistent state.
////////////////////////////////////////////////////////////////////////////////
lazy_static! {
    // Hashmap of session IDs (handles) mapped to sessions
    // TODO: Remove expired sessions from hashmap
    // XXX: Do we really need a session ID?
    static ref SESSIONS: Mutex<HashMap<SessionId, Session>> =
        Mutex::new(HashMap::new());
    static ref SESSION_COUNTER: AtomicU32 = AtomicU32::new(0);
}

pub type SessionId = u32;

pub struct Session {
    /// TLS session. Exposes a transparent I/O abstraction that simplifies the use of TLS: just read/write from/to it
    tls_context: Context<TcpStream>,
}

fn generate_tls_client_config() -> Result<Config> {
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

    config.set_min_version(Version::Tls13)?;
    config.set_max_version(Version::Tls13)?;

    let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
    let rng = Arc::new(mbedtls::rng::CtrDrbg::new(entropy, None)?);
    config.set_rng(rng);

    let cert = Arc::new(Certificate::from_pem_multiple(tls::ROOT_CA_CERT.as_bytes())?);
    config.set_ca_list(cert, None);

    let dbg_callback =
    |level: i32, file: Cow<'_, str>, line: i32, message: Cow<'_, str>| {
        print!("{} {}:{} {}", level, file, line, message);
    };
    config.set_dbg_callback(dbg_callback);
    unsafe { mbedtls::set_global_debug_threshold(5); }

    Ok(config)
}

fn generate_tls_server_config() -> Result<Config> {
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

    config.set_min_version(Version::Tls13)?;
    config.set_max_version(Version::Tls13)?;

    let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
    let rng = mbedtls::rng::CtrDrbg::new(entropy, None)?;
    config.set_rng(Arc::new(rng));

    let cert = Arc::new(Certificate::from_pem_multiple(tls::PEM_CERT.as_bytes())?);
    let key = Arc::new(
        Pk::from_private_key(
            &mut mbedtls::rng::CtrDrbg::new(Arc::new(mbedtls::rng::OsEntropy::new()), None)?,
            tls::PEM_KEY.as_bytes(),
            None)?);
    config.push_cert(cert, key)?;

    let dbg_callback =
    |level: i32, file: Cow<'_, str>, line: i32, message: Cow<'_, str>| {
        print!("{} {}:{} {}", level, file, line, message);
    };
    config.set_dbg_callback(dbg_callback);
    unsafe { mbedtls::set_global_debug_threshold(5); }

    Ok(config)
}

impl Session {
    /// Create session from responder's URL. Used by the initiator to attest the responder and establish a secure channel with the responder.
    /// Due to the way attested TLS is implemented, the TLS client is the attester and the TLS server is the relying party side. Additionally, mutual attestation is not supported
    pub fn from_url(responder_url: &str) -> Result<SessionId> {
        // Connect to responder
        let socket = TcpStream::connect(responder_url)
            .map_err(|e| anyhow!("Could not connect to responder on {}: {}", responder_url, e))?;
        info!("Connected to responder on {}.", responder_url);

        info!("Establishing TLS server context...");
        let config = generate_tls_server_config()?;
        let mut tls_context = Context::new(Arc::new(config));
        tls_context.establish(socket, None)?;
        info!("TLS server context established");

        // Add session to hashmap
        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .map_err(|_| anyhow!("Could not lock session hash table"))?
            .insert(session_id, Self { tls_context });
        info!("Session added to hashmap");

        Ok(session_id)
    }

    /// Create session from socket. Used by the responder to get attested and establish a secure channel with the initiator. Cf. `Session::from_url()` for more details
    pub fn from_socket(socket: TcpStream) -> Result<SessionId> {
        // Establish TLS client context
        info!("Establishing TLS client context...");
        let config = generate_tls_client_config()?;
        let mut tls_context = Context::new(Arc::new(config));
        tls_context.establish(socket, None)?;
        info!("TLS client context established");

        // Add session to hashmap
        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .map_err(|_| anyhow!("Could not lock session hash table"))?
            .insert(session_id, Self { tls_context });

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