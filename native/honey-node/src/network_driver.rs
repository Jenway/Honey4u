use super::*;
use honey_node::transport::LocalTcpTransport;

mod config;
mod result;
mod round;
mod types;
mod wire;

use config::{
    parse_broadcast_pool_config, parse_byzantine_node_config, parse_network_fault_config,
};
use result::build_node_result_json;
use round::{run_driver_rounds, wait_until_start};
use wire::parse_addresses_json;

pub(super) const DRIVER_NETWORK_BATCH_LIMIT: usize = 512;
pub(super) const DRIVER_IDLE_BACKOFF: Duration = Duration::from_micros(50);
pub(super) const BATCH_REF_TAG: u8 = 1;

pub(crate) fn run_rust_driver_node(args: RunDriverNodeArgs) -> Result<(), String> {
    let broadcast_pool_config = parse_broadcast_pool_config(&args.config_json)?;
    let network_fault_config = parse_network_fault_config(&args.config_json, args.pid)?;
    let byzantine_node_config = parse_byzantine_node_config(&args.config_json, args.pid)?;
    let addresses = parse_addresses_json(&args.addresses_json)?;
    let mut transport = LocalTcpTransport::new(args.pid, addresses, network_fault_config)
        .map_err(|err| err.to_string())?;
    let host = build_acs_host(
        args.acs_protocol,
        args.pid,
        args.nodes,
        args.faulty,
        &args.acs_crypto_json,
        &args.config_json,
    )?;
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
            let host_stats = host_stats?;
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
                return Err(format!(
                    "{err}; driver host shutdown failed: {shutdown_err}"
                ));
            }
            return Err(err);
        }
    };

    transport.close().map_err(|err| err.to_string())?;
    host_shutdown?;
    write_output(args.result_path.as_deref(), &rendered)
}
