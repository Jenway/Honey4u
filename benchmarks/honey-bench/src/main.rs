use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut argv = std::env::args();
    let _bin = argv.next();
    let Some(command) = argv.next() else {
        return Err(String::from("missing command; expected: run --config <path>").into());
    };
    if command != "run" {
        return Err(format!("unknown command: {command}; expected: run").into());
    }

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
    Err(format!(
        "could not locate honey-node; set HONEY_NODE_BINARY or build sibling binary at {}",
        sibling.display()
    ))
}
