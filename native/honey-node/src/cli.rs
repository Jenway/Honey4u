use super::*;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchDriverConfigFile {
    mode: Option<String>,
    sid: Option<String>,
    protocol: Option<String>,
    acs_protocol: Option<String>,
    nodes: Option<usize>,
    faulty: Option<usize>,
    rounds: Option<usize>,
    batch_size: Option<usize>,
    global_timeout: Option<f64>,
    result_path: Option<String>,
    ledger_dir: Option<String>,
    tx_json: Option<toml::Value>,
    config: Option<toml::Value>,
}

pub(crate) fn parse_cli<I>(mut argv: I) -> Result<CliCommand, String>
where
    I: Iterator<Item = String>,
{
    let _bin = argv.next();
    let Some(command) = argv.next() else {
        return Err(String::from("missing command"));
    };

    match command.as_str() {
        "run-driver-node" => parse_run_driver_node_args(argv).map(CliCommand::RunDriverNode),
        "bench-driver" => parse_bench_driver_args(argv).map(CliCommand::BenchDriver),
        _ => Err(format!("unknown command: {command}")),
    }
}

fn parse_run_driver_node_args<I>(mut argv: I) -> Result<RunDriverNodeArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut pid = 0usize;
    let mut sid = String::from("driver:hb");
    let mut acs_protocol = Protocol::HoneyBadger;
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
                acs_protocol = Protocol::parse(&take_value(&mut argv, "--acs-protocol")?)?;
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

    Ok(RunDriverNodeArgs {
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

fn parse_bench_driver_args<I>(mut argv: I) -> Result<BenchDriverArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut config_path: Option<String> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--config" => {
                if config_path.is_some() {
                    return Err(String::from(
                        "bench-driver accepts exactly one --config <path>",
                    ));
                }
                config_path = Some(take_value(&mut argv, "--config")?);
            }
            _ => {
                return Err(format!(
                    "bench-driver only supports --config <path>; found {arg}"
                ));
            }
        }
    }

    let config_path =
        config_path.ok_or_else(|| String::from("bench-driver requires --config <path>"))?;
    let file_config = load_bench_driver_config(&config_path)?;

    let mode = resolve_bench_mode(&file_config)?;
    let sid = file_config
        .sid
        .clone()
        .unwrap_or_else(|| String::from("bench:driver:hb"));
    let protocol = resolve_protocol(&file_config, "protocol")?.unwrap_or(Protocol::HoneyBadger);
    let acs_protocol =
        resolve_protocol(&file_config, "acs_protocol")?.unwrap_or(Protocol::HoneyBadger);
    let nodes = file_config.nodes.unwrap_or(4);
    let faulty = file_config.faulty.unwrap_or(1);
    let rounds = file_config.rounds.unwrap_or(1);
    let batch_size = file_config.batch_size.unwrap_or(1);
    let global_timeout = file_config.global_timeout.unwrap_or(30.0);
    let config_json = resolve_json_field(file_config.config.as_ref(), "config", "{}")?;
    let result_path = file_config.result_path.clone();
    let ledger_dir = file_config.ledger_dir.clone();
    let tx_json = resolve_optional_json_field(file_config.tx_json.as_ref(), "tx_json")?;

    if nodes == 0 {
        return Err(String::from("--nodes must be > 0"));
    }
    if rounds == 0 {
        return Err(String::from("--rounds must be > 0"));
    }
    if !matches!(mode, BenchDriverMode::Acs) && batch_size == 0 {
        return Err(String::from("--batch-size must be > 0"));
    }
    if global_timeout <= 0.0 {
        return Err(String::from("--global-timeout must be > 0"));
    }
    if !matches!(mode, BenchDriverMode::Dumbo) && (ledger_dir.is_some() || tx_json.is_some()) {
        return Err(String::from(
            "ledger_dir/tx_json are supported only with bench-driver mode \"dumbo\"",
        ));
    }

    Ok(BenchDriverArgs {
        mode,
        sid,
        protocol,
        acs_protocol,
        nodes,
        faulty,
        rounds,
        batch_size,
        global_timeout,
        config_json,
        result_path,
        ledger_dir,
        tx_json,
    })
}

fn load_bench_driver_config(path: &str) -> Result<BenchDriverConfigFile, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read bench-driver config '{path}': {err}"))?;
    toml::from_str(&content)
        .map_err(|err| format!("failed to parse bench-driver config '{path}': {err}"))
}

fn resolve_bench_mode(file_config: &BenchDriverConfigFile) -> Result<BenchDriverMode, String> {
    match file_config.mode.as_deref() {
        Some(value) => BenchDriverMode::parse(value),
        None => Ok(BenchDriverMode::Benchmark),
    }
}

fn resolve_protocol(
    file_config: &BenchDriverConfigFile,
    field_name: &str,
) -> Result<Option<Protocol>, String> {
    match field_name {
        "protocol" => file_config.protocol.as_deref(),
        "acs_protocol" => file_config.acs_protocol.as_deref(),
        _ => None,
    }
    .map(Protocol::parse)
    .transpose()
}

fn resolve_json_field(
    file_value: Option<&toml::Value>,
    field_name: &str,
    default: &str,
) -> Result<String, String> {
    match file_value {
        Some(value) => toml_value_to_json_string(value, field_name),
        None => Ok(String::from(default)),
    }
}

fn resolve_optional_json_field(
    file_value: Option<&toml::Value>,
    field_name: &str,
) -> Result<Option<String>, String> {
    file_value
        .map(|value| toml_value_to_json_string(value, field_name))
        .transpose()
}

fn toml_value_to_json_string(value: &toml::Value, field_name: &str) -> Result<String, String> {
    match value {
        toml::Value::String(value) => Ok(value.clone()),
        _ => serde_json::to_string(value).map_err(|err| {
            format!("failed to convert bench-driver field '{field_name}' to JSON: {err}")
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_path(file_name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("honey-node-{file_name}-{unique}.toml"))
    }

    #[test]
    fn parse_bench_driver_args_supports_toml_config_file() {
        let path = temp_config_path("bench-config");
        std::fs::write(
            &path,
            r#"
mode = "dumbo"
sid = "bench:file"
nodes = 5
faulty = 1
rounds = 2
batch_size = 3
global_timeout = 45.0
ledger_dir = "/tmp/ledger"
tx_json = [["tx-0"], ["tx-1"]]

[config]
enable_broadcast_pool_reuse = true
pool_grace_ms = 125
"#,
        )
        .expect("config file should write");

        let parsed = parse_bench_driver_args(
            vec!["--config".to_string(), path.to_string_lossy().into_owned()].into_iter(),
        )
        .expect("config file should parse");

        let _ = std::fs::remove_file(&path);

        assert!(matches!(parsed.mode, BenchDriverMode::Dumbo));
        assert_eq!(parsed.sid, "bench:file");
        assert_eq!(parsed.nodes, 5);
        assert_eq!(parsed.rounds, 2);
        assert_eq!(parsed.batch_size, 3);
        assert_eq!(parsed.global_timeout, 45.0);
        assert_eq!(parsed.ledger_dir.as_deref(), Some("/tmp/ledger"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&parsed.config_json).expect("valid JSON"),
            serde_json::json!({
                "enable_broadcast_pool_reuse": true,
                "pool_grace_ms": 125,
            })
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                parsed
                    .tx_json
                    .as_deref()
                    .expect("tx_json should be present")
            )
            .expect("valid JSON"),
            serde_json::json!([["tx-0"], ["tx-1"]])
        );
    }

    #[test]
    fn parse_bench_driver_args_requires_config_file() {
        let error = parse_bench_driver_args(Vec::<String>::new().into_iter())
            .err()
            .expect("config required");

        assert_eq!(error, "bench-driver requires --config <path>");
    }

    #[test]
    fn parse_bench_driver_args_rejects_legacy_flags() {
        let path = temp_config_path("bench-config-override");
        std::fs::write(
            &path,
            r#"
mode = "hb"
sid = "bench:file"
nodes = 5
faulty = 1
rounds = 2
batch_size = 3
global_timeout = 45.0

[config]
pool_grace_ms = 125
"#,
        )
        .expect("config file should write");

        let error = parse_bench_driver_args(
            vec![
                "--config".to_string(),
                path.to_string_lossy().into_owned(),
                "--nodes".to_string(),
            ]
            .into_iter(),
        )
        .err()
        .expect("legacy flags should be rejected");

        let _ = std::fs::remove_file(&path);

        assert_eq!(
            error,
            "bench-driver only supports --config <path>; found --nodes"
        );
    }
}
