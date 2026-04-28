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

fn cmd_tps(argv: std::env::Args) -> Result<(), Box<dyn std::error::Error>> {
    honey_bench::tps_cmd::cmd_tps(argv)
}

fn resolve_node_binary() -> Result<PathBuf, String> {
    honey_bench::resolve_node_binary()
}
