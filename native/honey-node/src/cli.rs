use super::*;

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
    let mut mode = BenchDriverMode::Benchmark;
    let mut sid = String::from("bench:driver:hb");
    let mut protocol = Protocol::HoneyBadger;
    let mut acs_protocol = Protocol::HoneyBadger;
    let mut nodes = 4usize;
    let mut faulty = 1usize;
    let mut rounds = 1usize;
    let mut batch_size = 1usize;
    let mut global_timeout = 30.0f64;
    let mut config_json = String::from("{}");
    let mut result_path: Option<String> = None;
    let mut ledger_dir: Option<String> = None;
    let mut tx_json: Option<String> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--mode" => {
                mode = BenchDriverMode::parse(&take_value(&mut argv, "--mode")?)?;
            }
            "--sid" => {
                sid = take_value(&mut argv, "--sid")?;
            }
            "--protocol" => {
                protocol = Protocol::parse(&take_value(&mut argv, "--protocol")?)?;
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
            "--config-json" => {
                config_json = take_value(&mut argv, "--config-json")?;
            }
            "--result-path" => {
                result_path = Some(take_value(&mut argv, "--result-path")?);
            }
            "--ledger-dir" => {
                ledger_dir = Some(take_value(&mut argv, "--ledger-dir")?);
            }
            "--tx-json" => {
                tx_json = Some(take_value(&mut argv, "--tx-json")?);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

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
            "--ledger-dir/--tx-json are supported only with bench-driver --mode dumbo",
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
