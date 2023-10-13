//! DPU-specific material for the Runtime Manager enclave
//!
//! NB: note that the attestation flow presented in this
//! module is *completely* insecure and just presented here as a
//! mockup of what a real attestation flow should look like.  See
//! the AWS Nitro Enclave attestation flow for a real example.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result};
use clap::Arg;
use hex::decode_to_slice;
use lazy_static::lazy_static;
use log::{debug, error, info};
use std::{net::TcpListener, sync::Mutex};

mod dpu_runtime;

lazy_static! {
    static ref RUNTIME_MANAGER_MEASUREMENT: Mutex<Vec<u8>> = Mutex::new(vec![0u8; 32]);
}

/// IP address for use by DPU.
const DPU_SERVER_ADDRESS: &str = "127.0.0.1";
const DPU_SERVER_PORT: i32 = 6666;

////////////////////////////////////////////////////////////////////////////////
// Entry point and message dispatcher.
////////////////////////////////////////////////////////////////////////////////

fn main() -> Result<(), String> {
    dpu_main().map_err(|err| {
        format!(
            "DPU Runtime Manager::main encap returned error:{:?}",
            err
        )
    })
}

/// Main entry point for DPU: parses command line arguments to find the port
/// number we should be listening on for incoming connections from the Veracruz
/// server.  Parses incoming messages, and acts on them.
pub fn dpu_main() -> Result<()> {
    env_logger::init();

    // init_session_manager()?;

    let matches = clap::Command::new("DPU runtime manager enclave")
        .author("The Veracruz Development Team")
        /*.arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .num_args(1)
                .required(true)
                .help("Address for connecting to Veracruz Server.")
                .value_name("ADDRESS"),
        )*/
        .arg(
            Arg::new("runtime_manager_measurement")
                .short('m')
                .long("measurement")
                .num_args(1)
                .required(true)
                .help("SHA256 measurement of the Runtime Manager enclave binary.")
                .value_name("MEASUREMENT"),
        )
        .get_matches();

    /*let address = if let Some(address) = matches.get_one::<String>("address") {
        address
    } else {
        error!("No address given. Exiting...");
        return Err(anyhow!("RuntimeManagerError::CommandLineArguments"));
    };*/

    let measurement =
        if let Some(measurement) = matches.get_one::<String>("runtime_manager_measurement") {
            measurement
        } else {
            error!("No measurement given. Exiting...");
            return Err(anyhow!("RuntimeManagerError::CommandLineArguments"));
        };

    let mut measurement_bytes = vec![0u8; 32];

    if let Err(err) = decode_to_slice(measurement, &mut measurement_bytes) {
        error!(
            "Failed to decode Runtime Manager measurement ({}).  Error produced: {:?}.",
            measurement, err
        );
        return Err(anyhow!("RuntimeManagerError::CommandLineArguments"));
    }

    {
        let mut rmm = RUNTIME_MANAGER_MEASUREMENT.lock().unwrap();
        *rmm = measurement_bytes;
    }

    let dpu_runtime = dpu_runtime::DPURuntime::new()?;

    let address = format!("{}:{}", DPU_SERVER_ADDRESS, DPU_SERVER_PORT);
    let listener = TcpListener::bind(&address).map_err(|e| {
        anyhow!("Could not bind TCP listener: {}", e)
    })?;
    info!("TCP listener created on {}.", address);

    debug!("dpu_runtime_manager::dpu_main accept succeeded. looping");
    loop {
        let (mut runtime_manager_socket, _) = listener.accept().map_err(|ioerr| {
            anyhow!(
                "Failed to accept any incoming TCP connection.  Error produced: {}.",
                ioerr
            )
        })?;
        info!("Accepted connection from host.");

        // Configure TCP to flush outgoing buffers immediately. This reduces latency
        // when dealing with small packets
        let _ = runtime_manager_socket.set_nodelay(true);

        debug!("DPU Runtime Manager::main accept succeeded. Looping");
        loop {
            dpu_runtime.decode_dispatch(&mut runtime_manager_socket)?;
        }
    }
}
