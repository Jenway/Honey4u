mod cli;

use cli::parse_args;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let node_binary = if args.list_experiments || args.dry_run {
        std::path::PathBuf::new()
    } else {
        honey_bench::resolve_node_binary(args.node_binary.as_deref())?
    };
    honey_bench::suite::run_suite(&args.suite_config, &node_binary, args.suite_opts())
        .map_err(Into::into)
}
