// Manage transport session.

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use log::info;
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::HashMap, net::TcpStream, sync::{Mutex, atomic::{AtomicU32, Ordering}}};

use crate::tcp;

////////////////////////////////////////////////////////////////////////////////
// Various bits of persistent state.
////////////////////////////////////////////////////////////////////////////////
lazy_static! {
    // Hashmap of session IDs mapped to sessions
    static ref SESSIONS: Mutex<HashMap<SessionId, Session>> =
        Mutex::new(HashMap::new());
    static ref SESSION_COUNTER: AtomicU32 = AtomicU32::new(0);
}

pub type SessionId = u32;

pub struct Session {
    /// Client socket connecting to the server. 
    socket: TcpStream,
}

impl Session {
    /// Create session from server URL. Suitable for clients
    pub fn from_url(server_url: &str) -> Result<u32> {
        // Create socket and connect to endpoint
        let socket = TcpStream::connect(server_url)
            .map_err(|e| anyhow!("Could not connect to server on {}: {}", server_url, e))?;
        info!("Connected to server on {}.", server_url);
        
        // Add session to hashmap
        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .map_err(|_| anyhow!("Could not lock session hash table"))?
            .insert(session_id, Self { socket });
        Ok(session_id)
    }

    /// Create session from socket. Suitable for servers
    pub fn from_socket(socket: TcpStream) -> Result<u32> {
        // Configure TCP to flush outgoing buffers immediately. This reduces
        // latency when dealing with small packets
        let _ = socket.set_nodelay(true);

        // Add session to hashmap
        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .map_err(|_| anyhow!("Could not lock session hash table"))?
            .insert(session_id, Self { socket });
        Ok(session_id)
    }

    pub fn get_mut_socket(&mut self) -> &mut TcpStream {
        &mut self.socket
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
        let socket = s.get_mut_socket();
        tcp::send_message(socket, data)
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
        let socket = s.get_mut_socket();
        tcp::receive_message(socket)
    }
}