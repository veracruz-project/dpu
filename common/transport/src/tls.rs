//! Common TLS functionality
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
use mbedtls::ssl::Context;
use serde::{de::DeserializeOwned, Serialize};
use std::net::TcpStream;

// XXX: this is very ugly
pub const ROOT_CA_CERT: &'static str = concat!(include_str!("../keys/ca.crt"),"\0");
pub const PEM_KEY: &'static str = concat!(include_str!("../keys/user.key"),"\0");
pub const PEM_CERT: &'static str = concat!(include_str!("../keys/user.crt"),"\0");

/// Transmits a serialized message, `data`, via a socket.
///
/// Fails if the message cannot be serialized, or if the serialized message
/// cannot be transmitted.
pub (crate) fn send_message<T>(tls_context: &mut Context<TcpStream>, data: T) -> Result<()>
where
    T: Serialize,
{
    debug!("Sending message on {:?} through TLS", tls_context.io());

    let message = serialize(&data).map_err(|e| {
        error!("Failed to serialize message.  Error produced: {}.", e);
        e
    })?;

    send_buffer(tls_context, &message).map_err(|e| {
        error!("Failed to send message.  Error produced: {}.", e);
        e
    })?;

    Ok(())
}

/// Receives and deserializes a message via a socket.
///
/// Fails if no message can be received, or if the received message cannot be
/// deserialized.
pub (crate) fn receive_message<T>(tls_context: &mut Context<TcpStream>) -> Result<T>
where
    T: DeserializeOwned,
{
    debug!("Receiving message on {:?} through TLS", tls_context.io());

    let buffer = receive_buffer(tls_context)
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