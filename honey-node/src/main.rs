mod cli;
mod driver_node;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::parse_args();
    args.validate()?;
    driver_node::run_driver_node(args)?;
    Ok(())
}
