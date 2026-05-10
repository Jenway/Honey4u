use clap::Parser;
use honey_bench::suite::SuiteRunOpts;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "honey-bench")]
pub(crate) struct CliArgs {
    #[arg(long, required = true)]
    pub(crate) suite_config: PathBuf,
    #[arg(long)]
    pub(crate) node_binary: Option<PathBuf>,
    #[arg(long, value_delimiter = ',')]
    pub(crate) experiments: Option<Vec<String>>,
    #[arg(long)]
    pub(crate) list_experiments: bool,
    #[arg(long)]
    pub(crate) dry_run: bool,
    #[arg(long)]
    pub(crate) max_runs: Option<usize>,
    #[arg(long)]
    pub(crate) output_dir: Option<PathBuf>,
}

impl CliArgs {
    pub(crate) fn suite_opts(&self) -> SuiteRunOpts {
        SuiteRunOpts {
            experiments: self.experiments.clone(),
            list_only: self.list_experiments,
            dry_run: self.dry_run,
            max_runs: self.max_runs,
            output_dir: self.output_dir.clone(),
        }
    }
}

pub(crate) fn parse_args() -> CliArgs {
    CliArgs::parse()
}
