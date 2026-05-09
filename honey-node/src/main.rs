mod cli;
mod driver;

use serde_json::json;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::parse_args();
    let result_path = args.result_path.clone();
    let pid = args.pid;
    let batch_size = args.batch_size;
    let result = match args.validate() {
        Ok(()) => driver::run_driver_node(args).map_err(|err| err.to_string()),
        Err(err) => Err(err),
    };
    if let Err(message) = &result {
        write_early_failure_result(result_path.as_deref(), pid, batch_size, message);
    }
    result.map_err(|message| std::io::Error::other(message).into())
}

fn write_early_failure_result(
    result_path: Option<&str>,
    pid: usize,
    batch_size: usize,
    message: &str,
) {
    let Some(result_path) = result_path else {
        return;
    };
    let path = Path::new(result_path);
    if path.exists() {
        return;
    }
    let payload = json!({
        "pid": pid,
        "status": "error",
        "batch_size": batch_size,
        "error": {
            "kind": "startup",
            "message": message,
        },
    });
    if let Ok(rendered) = serde_json::to_string(&payload) {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, rendered);
    }
}
