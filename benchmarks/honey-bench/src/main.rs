use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut argv = std::env::args();
    let _bin = argv.next();
    let Some(command) = argv.next() else {
        return Err(String::from(
            "missing command; expected: run --config <path>  |  suite --suite-config <path>  |  tps [OPTIONS]",
        )
        .into());
    };
    match command.as_str() {
        "run" => cmd_run(argv),
        "suite" => cmd_suite(argv),
        "tps" => cmd_tps(argv),
        _ => Err(format!("unknown command: {command}; expected: run | suite | tps").into()),
    }
}

fn cmd_run(mut argv: std::env::Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut config_path: Option<String> = None;
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--config" => {
                if config_path.is_some() {
                    return Err(String::from("run accepts exactly one --config <path>").into());
                }
                config_path = Some(
                    argv.next()
                        .ok_or_else(|| String::from("--config requires a value"))?,
                );
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    let config_path = config_path.ok_or_else(|| String::from("run requires --config <path>"))?;
    let node_binary = resolve_node_binary()?;
    honey_bench::run_config_path(Path::new(&config_path), &node_binary).map_err(Into::into)
}

fn cmd_suite(mut argv: std::env::Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut suite_config: Option<String> = None;
    let mut experiments: Option<Vec<String>> = None;
    let mut list_only = false;
    let mut dry_run = false;
    let mut max_runs: Option<usize> = None;
    let mut output_dir: Option<PathBuf> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--suite-config" => {
                if suite_config.is_some() {
                    return Err(
                        String::from("suite accepts exactly one --suite-config <path>").into(),
                    );
                }
                suite_config = Some(
                    argv.next()
                        .ok_or_else(|| String::from("--suite-config requires a value"))?,
                );
            }
            "--experiments" => {
                if experiments.is_some() {
                    return Err(String::from("--experiments may only be specified once").into());
                }
                let raw = argv.next().ok_or_else(|| {
                    String::from("--experiments requires a comma-separated value")
                })?;
                experiments = Some(raw.split(',').map(|s| s.trim().to_owned()).collect());
            }
            "--list-experiments" => {
                list_only = true;
            }
            "--dry-run" => {
                dry_run = true;
            }
            "--max-runs" => {
                let raw = argv
                    .next()
                    .ok_or_else(|| String::from("--max-runs requires a value"))?;
                let n: usize = raw
                    .parse()
                    .map_err(|_| format!("--max-runs: expected a positive integer, got {raw:?}"))?;
                max_runs = Some(n);
            }
            "--output-dir" => {
                if output_dir.is_some() {
                    return Err(String::from("--output-dir may only be specified once").into());
                }
                let raw = argv
                    .next()
                    .ok_or_else(|| String::from("--output-dir requires a value"))?;
                output_dir = Some(PathBuf::from(raw));
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }

    let suite_config =
        suite_config.ok_or_else(|| String::from("suite requires --suite-config <path>"))?;
    // Resolve node binary lazily: not needed for --list-experiments or --dry-run.
    let node_binary = if list_only || dry_run {
        PathBuf::new()
    } else {
        resolve_node_binary()?
    };
    let opts = honey_bench::suite::SuiteRunOpts {
        experiments,
        list_only,
        dry_run,
        max_runs,
        output_dir,
    };
    honey_bench::suite::run_suite(Path::new(&suite_config), &node_binary, opts).map_err(Into::into)
}

/// `honey-bench tps` — run a single benchmark with comprehensive statistics.
///
/// Accepts a subset of the most common benchmark parameters as CLI flags,
/// generates a TOML config internally, runs the benchmark, and prints
/// a structured JSON result to stdout.
fn cmd_tps(mut argv: std::env::Args) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let mut nodes: Option<usize> = None;
    let mut faulty: Option<usize> = None;
    let mut batch_size: Option<usize> = None;
    let mut rounds: Option<usize> = None;
    let mut warmup_rounds: usize = 0;
    let mut global_timeout: Option<f64> = None;
    let mut protocol: &str = "dumbo";
    let mut backend: &str = "rust_fin";
    let mut reuse: bool = false;
    let mut pool_grace_ms: u64 = 200;
    let mut sid: Option<String> = None;
    let mut output_json: Option<String> = None;
    let mut result_path: Option<String> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                eprintln!("honey-bench tps [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --nodes N            number of nodes [default: 4]");
                eprintln!("  --faulty F           fault tolerance [default: (N-1)/3]");
                eprintln!("  --batch-size B       transactions per node per round [default: 1]");
                eprintln!("  --rounds R           number of rounds [default: 1]");
                eprintln!("  --warmup-rounds W    warmup rounds to exclude [default: 0]");
                eprintln!("  --global-timeout T   overall timeout seconds [default: 30]");
                eprintln!("  --protocol P         hb or dumbo [default: dumbo]");
                eprintln!("  --backend B          rust_fin, rust_dumbo, python [default: rust_fin]");
                eprintln!("  --enable-pool-reuse  enable broadcast pool reuse");
                eprintln!("  --pool-grace-ms MS   grace period ms [default: 200]");
                eprintln!("  --sid S              benchmark session id");
                eprintln!("  --output-json PATH   write JSON output to file");
                return Ok(());
            }
            "--nodes" => nodes = Some(argv.next().ok_or("--nodes requires a value")?.parse()?),
            "--faulty" => faulty = Some(argv.next().ok_or("--faulty requires a value")?.parse()?),
            "--batch-size" => batch_size = Some(argv.next().ok_or("--batch-size requires a value")?.parse()?),
            "--rounds" => rounds = Some(argv.next().ok_or("--rounds requires a value")?.parse()?),
            "--warmup-rounds" => warmup_rounds = argv.next().ok_or("--warmup-rounds requires a value")?.parse()?,
            "--global-timeout" => global_timeout = Some(argv.next().ok_or("--global-timeout requires a value")?.parse()?),
            "--protocol" => protocol = argv.next().ok_or("--protocol requires a value")?.leak(),
            "--backend" => backend = argv.next().ok_or("--backend requires a value")?.leak(),
            "--enable-pool-reuse" => reuse = true,
            "--pool-grace-ms" => pool_grace_ms = argv.next().ok_or("--pool-grace-ms requires a value")?.parse()?,
            "--sid" => sid = Some(argv.next().ok_or("--sid requires a value")?),
            "--output-json" => output_json = Some(argv.next().ok_or("--output-json requires a value")?),
            "--result-path" => result_path = Some(argv.next().ok_or("--result-path requires a value")?),
            a if a.starts_with('-') => return Err(format!("unknown tps flag: {a}").into()),
            _ => return Err(format!("unexpected positional argument: {arg}").into()),
        }
    }

    let nodes = nodes.unwrap_or(4);
    let faulty = faulty.unwrap_or_else(|| (nodes - 1) / 3);
    let batch_size = batch_size.unwrap_or(1);
    let rounds = rounds.unwrap_or(1);
    let global_timeout = global_timeout.unwrap_or(30.0);
    let sid = sid.unwrap_or_else(|| format!("tps:{protocol}:{backend}:n{nodes}"));
    let config_json = format!(
        r#"{{"acs_backend":"{backend}","enable_broadcast_pool_reuse":{reuse},"enable_pool_reference_proposals":{reuse},"enable_pool_fetch_fallback":{reuse},"pool_grace_ms":{pool_grace_ms},"pool_reuse_limit_per_round":4,"pool_expire_rounds":10,"pool_mempool_max":1024}}"#
    );

    let node_binary = resolve_node_binary()?;
    let args = honey_bench::BenchDumboArgs {
        sid: sid.clone(),
        nodes,
        faulty,
        rounds,
        batch_size,
        global_timeout: global_timeout + 10.0, // add buffer for process startup
        config_json,
        result_path,
        ledger_dir: None,
        tx_json: None,
    };

    // Run the benchmark
    let result_json_str =
        honey_bench::run_drive_dumbo_multiprocess(&args, &node_binary)
        .map_err(|e| e)?;

    // Parse result and compute statistics
    let raw: serde_json::Value =
        serde_json::from_str(&result_json_str).map_err(|e| format!("parse result: {e}"))?;

    let tps_result = honey_bench::tps::build_tps_result(&raw, warmup_rounds, backend);
    // Patch in the CLI-level metadata
    let tps_result = honey_bench::tps::TpsResult {
        batch_size,
        global_timeout,
        pool_grace_ms,
        ..tps_result
    };

    let output = honey_bench::tps::tps_result_to_json(&tps_result);
    let rendered = serde_json::to_string_pretty(&output)?;

    if let Some(path) = output_json {
        std::fs::write(&path, &rendered).map_err(|e| format!("write {path}: {e}"))?;
        eprintln!("[tps] wrote {}", path);
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(rendered.as_bytes())?;
        handle.write_all(b"\n")?;
    }

    Ok(())
}

fn resolve_node_binary() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("HONEY_NODE_BINARY") {
        let path = PathBuf::from(value);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "HONEY_NODE_BINARY points to missing path: {}",
            path.display()
        ));
    }
    let current = std::env::current_exe().map_err(|err| err.to_string())?;
    let sibling = current.with_file_name("honey-node");
    if sibling.exists() {
        return Ok(sibling);
    }
    let sibling_exe = current.with_file_name("honey-node.exe");
    if sibling_exe.exists() {
        return Ok(sibling_exe);
    }
    Err(format!(
        "could not locate honey-node; set HONEY_NODE_BINARY or build sibling binary at {}",
        sibling.display()
    ))
}
