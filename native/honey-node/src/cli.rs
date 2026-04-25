use crate::acs::protocol::AcsProtocol;
use crate::node_runtime::args::NodeRuntimeArgs;

pub(crate) fn parse_cli<I>(mut argv: I) -> Result<NodeRuntimeArgs, String>
where
    I: Iterator<Item = String>,
{
    let _bin = argv.next();
    let Some(command) = argv.next() else {
        return Err(String::from("missing command"));
    };

    match command.as_str() {
        "run-driver-node" => parse_run_driver_node_args(argv),
        _ => Err(format!("unknown command: {command}")),
    }
}

fn take_value<I>(argv: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    argv.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_usize_flag<I>(argv: &mut I, flag: &str) -> Result<usize, String>
where
    I: Iterator<Item = String>,
{
    let value = take_value(argv, flag)?;
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn parse_u64_flag<I>(argv: &mut I, flag: &str) -> Result<u64, String>
where
    I: Iterator<Item = String>,
{
    let value = take_value(argv, flag)?;
    value
        .parse::<u64>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn parse_f64_flag<I>(argv: &mut I, flag: &str) -> Result<f64, String>
where
    I: Iterator<Item = String>,
{
    let value = take_value(argv, flag)?;
    value
        .parse::<f64>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn parse_run_driver_node_args<I>(mut argv: I) -> Result<NodeRuntimeArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut pid = 0usize;
    let mut sid = String::from("driver:hb");
    let mut acs_protocol = AcsProtocol::HoneyBadger;
    let mut nodes = 4usize;
    let mut faulty = 1usize;
    let mut rounds = 1usize;
    let mut batch_size = 1usize;
    let mut global_timeout = 30.0f64;
    let mut addresses_json: Option<String> = None;
    let mut hb_crypto_json: Option<String> = None;
    let mut acs_crypto_json: Option<String> = None;
    let mut config_json = String::from("{}");
    let mut start_at_ms: Option<u64> = None;
    let mut result_path: Option<String> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--pid" => {
                pid = parse_usize_flag(&mut argv, "--pid")?;
            }
            "--sid" => {
                sid = take_value(&mut argv, "--sid")?;
            }
            "--acs-protocol" => {
                acs_protocol = AcsProtocol::parse(&take_value(&mut argv, "--acs-protocol")?)?;
            }
            "--nodes" => {
                nodes = parse_usize_flag(&mut argv, "--nodes")?;
            }
            "--faulty" => {
                faulty = parse_usize_flag(&mut argv, "--faulty")?;
            }
            "--rounds" => {
                rounds = parse_usize_flag(&mut argv, "--rounds")?;
            }
            "--batch-size" => {
                batch_size = parse_usize_flag(&mut argv, "--batch-size")?;
            }
            "--global-timeout" => {
                global_timeout = parse_f64_flag(&mut argv, "--global-timeout")?;
            }
            "--addresses-json" => {
                addresses_json = Some(take_value(&mut argv, "--addresses-json")?);
            }
            "--hb-crypto-json" => {
                hb_crypto_json = Some(take_value(&mut argv, "--hb-crypto-json")?);
            }
            "--acs-crypto-json" => {
                acs_crypto_json = Some(take_value(&mut argv, "--acs-crypto-json")?);
            }
            "--config-json" => {
                config_json = take_value(&mut argv, "--config-json")?;
            }
            "--start-at-ms" => {
                start_at_ms = Some(parse_u64_flag(&mut argv, "--start-at-ms")?);
            }
            "--result-path" => {
                result_path = Some(take_value(&mut argv, "--result-path")?);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if nodes == 0 {
        return Err(String::from("--nodes must be > 0"));
    }
    if pid >= nodes {
        return Err(format!("--pid {pid} must be < --nodes {nodes}"));
    }
    if rounds == 0 {
        return Err(String::from("--rounds must be > 0"));
    }
    if batch_size == 0 {
        return Err(String::from("--batch-size must be > 0"));
    }
    if global_timeout <= 0.0 {
        return Err(String::from("--global-timeout must be > 0"));
    }

    Ok(NodeRuntimeArgs {
        pid,
        sid,
        acs_protocol,
        nodes,
        faulty,
        rounds,
        batch_size,
        global_timeout,
        addresses_json: addresses_json
            .ok_or_else(|| String::from("--addresses-json is required"))?,
        hb_crypto_json: hb_crypto_json
            .ok_or_else(|| String::from("--hb-crypto-json is required"))?,
        acs_crypto_json: acs_crypto_json
            .ok_or_else(|| String::from("--acs-crypto-json is required"))?,
        config_json,
        start_at_ms,
        result_path,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_cli;

    fn minimal_args() -> Vec<String> {
        vec![
            "honey-node".to_string(),
            "run-driver-node".to_string(),
            "--pid".to_string(),
            "0".to_string(),
            "--nodes".to_string(),
            "1".to_string(),
            "--faulty".to_string(),
            "0".to_string(),
            "--rounds".to_string(),
            "1".to_string(),
            "--batch-size".to_string(),
            "1".to_string(),
            "--addresses-json".to_string(),
            "[[\"127.0.0.1\", 10000]]".to_string(),
            "--hb-crypto-json".to_string(),
            "{}".to_string(),
            "--acs-crypto-json".to_string(),
            "{}".to_string(),
        ]
    }

    #[test]
    fn parse_cli_accepts_run_driver_node() {
        let parsed = parse_cli(minimal_args().into_iter()).expect("args should parse");

        assert_eq!(parsed.pid, 0);
        assert_eq!(parsed.nodes, 1);
        assert_eq!(parsed.batch_size, 1);
        assert_eq!(parsed.addresses_json, "[[\"127.0.0.1\", 10000]]");
    }

    #[test]
    fn parse_cli_rejects_bench_driver() {
        let error = parse_cli(
            vec![
                "honey-node".to_string(),
                "bench-driver".to_string(),
                "--config".to_string(),
                "bench.toml".to_string(),
            ]
            .into_iter(),
        )
        .err()
        .expect("bench-driver should be removed");

        assert_eq!(error, "unknown command: bench-driver");
    }
}
