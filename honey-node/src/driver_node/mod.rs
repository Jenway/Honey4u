use crate::driver_node::args::NodeRuntimeArgs;
use crate::driver_node::hb_shell::keys::parse_honeybadger_crypto_payload;
use crate::driver_node::output::write_output;
use honey_acs::build_acs_backend;
use honey_node::transport::LocalTcpTransport;
use std::time::Duration;

pub(crate) mod args;
mod clock;
mod config;
mod error;
pub(crate) mod hb_shell;
mod output;
pub(super) mod reuse;
mod round;
pub(crate) mod telemetry;
mod wire;

use clock::wait_until_start;
use config::{
    parse_broadcast_pool_config, parse_byzantine_node_config, parse_network_fault_config,
};
use error::{DriverError, DriverResult};
use output::build_node_result_json;
use round::run_driver_rounds;
use wire::frame::parse_addresses_json;

pub(super) const DRIVER_NETWORK_BATCH_LIMIT: usize = 512;
pub(super) const DRIVER_IDLE_BACKOFF: Duration = Duration::from_micros(50);

pub(crate) fn run_driver_node(args: NodeRuntimeArgs) -> DriverResult<()> {
    let broadcast_pool_config = parse_broadcast_pool_config(&args.config_json)?;
    let network_fault_config = parse_network_fault_config(&args.config_json, args.pid)?;
    let byzantine_node_config = parse_byzantine_node_config(&args.config_json, args.pid)?;
    let addresses = parse_addresses_json(&args.addresses_json)?;
    let mut transport = LocalTcpTransport::new(args.pid, addresses, network_fault_config)?;
    let host = build_acs_backend(
        args.acs_protocol,
        args.pid,
        args.nodes,
        args.faulty,
        &args.acs_crypto_json,
        &args.config_json,
    )
    .map_err(|message| DriverError::acs("backend build", message))?;
    let (public_key, private_share) = parse_honeybadger_crypto_payload(&args.hb_crypto_json)?;
    wait_until_start(args.start_at_ms)?;

    let result = run_driver_rounds(
        host.as_ref(),
        &transport,
        &public_key,
        &private_share,
        &args,
        &broadcast_pool_config,
        byzantine_node_config,
    );
    let host_stats = host.stats();
    let host_shutdown = host.shutdown();
    let rendered = match result {
        Ok((run_result, queue_peaks)) => {
            let host_stats = host_stats.map_err(|message| DriverError::acs("stats", message))?;
            build_node_result_json(
                args.pid,
                args.batch_size,
                run_result,
                host_stats,
                &transport,
                &queue_peaks,
            )?
        }
        Err(err) => {
            let _ = transport.close();
            if let Err(shutdown_err) = host_shutdown {
                return Err(DriverError::acs(
                    "shutdown",
                    format!("{err}; driver host shutdown failed: {shutdown_err}"),
                ));
            }
            return Err(err);
        }
    };

    transport.close()?;
    host_shutdown.map_err(|message| DriverError::acs("shutdown", message))?;
    write_output(args.result_path.as_deref(), &rendered)
}
