use crate::driver::args::NodeRuntimeArgs;
use crate::driver::encryption::keys::parse_honeybadger_crypto_payload;
use crate::driver::output::write_output;
use honey_acs::build_acs_backend;
#[cfg(feature = "quic")]
use honey_transport::QuicTransport;
use honey_transport::{FaultInjectedTransport, LocalTcpTransport, TransportHandle};
use std::sync::Arc;
use std::time::Duration;

pub(crate) mod args;
mod config;
mod encryption;
mod error;
mod frame;
mod mempool;
mod output;
mod round;

use config::{
    parse_broadcast_pool_config, parse_byzantine_node_config, parse_network_fault_config,
};
use error::{DriverError, DriverResult};
use frame::parse_addresses_json;
use output::{build_node_failure_json, build_node_result_json};
use round::run_driver_rounds;

pub(super) const DRIVER_NETWORK_BATCH_LIMIT: usize = 512;
pub(super) const DRIVER_IDLE_BACKOFF: Duration = Duration::from_micros(50);

pub(crate) fn run_driver_node(args: NodeRuntimeArgs) -> DriverResult<()> {
    let broadcast_pool_config = parse_broadcast_pool_config(&args.config_json)?;
    let network_fault_config = parse_network_fault_config(&args.config_json, args.pid)?;
    let byzantine_node_config = parse_byzantine_node_config(&args.config_json, args.pid)?;
    let addresses = parse_addresses_json(&args.addresses_json)?;
    let transport: Box<dyn TransportHandle> =
        create_transport(&args.config_json, args.pid, addresses, network_fault_config)?;
    let host = build_acs_backend(
        args.acs_backend,
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
        &*transport,
        &public_key,
        &private_share,
        &args,
        &broadcast_pool_config,
        byzantine_node_config,
    );
    let host_stats = host
        .stats()
        .map_err(|message| DriverError::acs("stats", message));
    let host_shutdown = host
        .shutdown()
        .map_err(|message| DriverError::acs("shutdown", message));

    match (result, host_stats, host_shutdown) {
        (Ok((run_result, queue_peaks)), Ok(host_stats), Ok(())) => {
            let rendered = build_node_result_json(
                args.pid,
                args.batch_size,
                run_result,
                host_stats,
                &*transport,
                &queue_peaks,
            )?;
            write_output(args.result_path.as_deref(), &rendered)
        }
        (result, host_stats, host_shutdown) => {
            let (primary_error, host_stats, host_stats_error, shutdown_error) =
                match (result, host_stats, host_shutdown) {
                    (Err(err), Ok(host_stats), Ok(())) => (err, Some(host_stats), None, None),
                    (Err(err), Ok(host_stats), Err(shutdown_err)) => {
                        (err, Some(host_stats), None, Some(shutdown_err.to_string()))
                    }
                    (Err(err), Err(stats_err), Ok(())) => {
                        (err, None, Some(stats_err.to_string()), None)
                    }
                    (Err(err), Err(stats_err), Err(shutdown_err)) => (
                        err,
                        None,
                        Some(stats_err.to_string()),
                        Some(shutdown_err.to_string()),
                    ),
                    (Ok(_), Err(stats_err), Ok(())) => (stats_err, None, None, None),
                    (Ok(_), Err(stats_err), Err(shutdown_err)) => {
                        (stats_err, None, None, Some(shutdown_err.to_string()))
                    }
                    (Ok(_), Ok(host_stats), Err(shutdown_err)) => {
                        (shutdown_err, Some(host_stats), None, None)
                    }
                    (Ok(_), Ok(_), Ok(())) => unreachable!(),
                };

            let rendered = build_node_failure_json(
                args.pid,
                args.batch_size,
                &primary_error,
                host_stats.as_ref(),
                host_stats_error.as_deref(),
                shutdown_error.as_deref(),
                &*transport,
            )?;
            let _ = write_output(args.result_path.as_deref(), &rendered);
            Err(primary_error)
        }
    }
}

fn resolve_transport_backend(config_json: &str) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(config_json)
        && let Some(transport) = value.get("transport").and_then(|v| v.as_str())
    {
        return transport.to_owned();
    }
    "tcp".to_owned()
}

fn create_transport(
    config_json: &str,
    pid: usize,
    addresses: Vec<(String, u16)>,
    network_fault_config: honey_transport::NetworkFaultConfig,
) -> DriverResult<Box<dyn TransportHandle>> {
    let backend = resolve_transport_backend(config_json);
    let base_transport: Box<dyn TransportHandle> = match backend.as_str() {
        "tcp" => Box::new(LocalTcpTransport::new(pid, addresses, Default::default())?),
        "quic" => {
            #[cfg(feature = "quic")]
            {
                Box::new(QuicTransport::new(pid, addresses, Default::default())?)
            }
            #[cfg(not(feature = "quic"))]
            {
                return Err(DriverError::config(
                    "transport=quic requested, but this honey-node binary was built without the quic feature",
                ));
            }
        }
        other => {
            return Err(DriverError::config(format!(
                "unsupported transport backend: {other}"
            )));
        }
    };
    if network_fault_config.is_active() {
        let inner: Arc<dyn TransportHandle> = Arc::from(base_transport);
        Ok(Box::new(FaultInjectedTransport::new(
            inner,
            network_fault_config,
            pid,
        )))
    } else {
        Ok(base_transport)
    }
}

use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn current_time_millis() -> DriverResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| DriverError::clock(err.to_string()))?;
    u64::try_from(duration.as_millis()).map_err(|_| DriverError::clock("current time overflow"))
}

pub(crate) fn wait_until_start(start_at_ms: Option<u64>) -> DriverResult<()> {
    let Some(start_at_ms) = start_at_ms else {
        return Ok(());
    };
    let now_ms = current_time_millis()?;
    if start_at_ms <= now_ms {
        return Ok(());
    }
    thread::sleep(Duration::from_millis(start_at_ms - now_ms));
    Ok(())
}
