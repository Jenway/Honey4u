mod cli;
mod driver;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::parse_args();
    args.validate()?;
    driver::run_driver_node(args)?;
    Ok(())
}
