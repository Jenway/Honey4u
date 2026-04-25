mod acs;
mod cli;
mod codec;
mod node_runtime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::parse_cli(std::env::args())?;
    node_runtime::run_rust_driver_node(args).map_err(Into::into)
}
