//! Common TCP socket-related functionality
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE.md` file in the Veracruz root directory for copyright
//! and licensing information.

use super::fd::{receive_buffer, send_buffer};
use anyhow::Result;
use bincode::{deserialize, serialize};
use log::{error, debug};
use serde::{de::DeserializeOwned, Serialize};
use std::net::TcpStream;

/// Transmits a serialized message, `data`, via a socket.
///
/// Fails if the message cannot be serialized, or if the serialized message
/// cannot be transmitted.
pub (crate) fn send_message<T>(socket: &mut TcpStream, data: T) -> Result<()>
where
    T: Serialize,
{
    debug!("Sending message on {:?}", socket);

    let message = serialize(&data).map_err(|e| {
        error!("Failed to serialize message.  Error produced: {}.", e);
        e
    })?;

    send_buffer(socket, &message).map_err(|e| {
        error!("Failed to send message.  Error produced: {}.", e);
        e
    })?;

    Ok(())
}

/// Receives and deserializes a message via a socket.
///
/// Fails if no message can be received, or if the received message cannot be
/// deserialized.
pub (crate) fn receive_message<T>(socket: &mut TcpStream) -> Result<T>
where
    T: DeserializeOwned,
{
    debug!("Receiving message on {:?}", socket);

    let buffer = receive_buffer(socket)
        .map_err(|e| {
            error!("Failed to receive buffer.  Error produced: {}.", e);
            e
        }
    )?;

    let message: T = deserialize(&buffer).map_err(|e| {
        error!("Failed to deserialize message.  Error produced: {}.", e);

        e
    })?;

    Ok(message)
}