use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut argv = std::env::args();
    let _bin = argv.next();
    let Some(command) = argv.next() else {
        return Err(String::from("missing command; expected: suite --suite-config <path>").into());
    };
    match command.as_str() {
        "suite" => cmd_suite(argv),
        _ => Err(format!("unknown command: {command}; expected: suite").into()),
    }
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

fn resolve_node_binary() -> Result<PathBuf, String> {
    honey_bench::resolve_node_binary()
}
