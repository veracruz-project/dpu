// Manage transport session.

use anyhow::{anyhow, Result};
use log::{error, info};
use std::net::TcpStream;

pub struct Session {
    /// Client socket connecting to the server. 
    socket: TcpStream,
}

impl Session {
    pub fn new(server_url: &str) -> Result<Self> {
        let socket = TcpStream::connect(server_url).map_err(|e| {
            error!("Could not connect to server on {}: {}", server_url, e);
            anyhow!(e)
        })?;
        info!("Connected to server on {}.", server_url);
        Ok(Self { socket })
    }

    pub fn get_mut_socket(&mut self) -> &mut TcpStream {
        &mut self.socket
    }
}