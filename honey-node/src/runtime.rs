use clap::Parser;
use serde_json::json;
use std::fs;
use std::path::Path;

pub use crate::driver::args::NodeRuntimeArgs;

pub fn run_node(args: NodeRuntimeArgs) -> Result<(), String> {
    let result_path = args.result_path.clone();
    let pid = args.pid;
    let batch_size = args.batch_size;
    let result = match args.validate() {
        Ok(()) => crate::driver::run_driver_node(args).map_err(|err| err.to_string()),
        Err(err) => Err(err),
    };
    if let Err(message) = &result {
        write_early_failure_result(result_path.as_deref(), pid, batch_size, message);
    }
    result
}

pub fn parse_node_args() -> NodeRuntimeArgs {
    NodeRuntimeArgs::parse()
}

pub fn current_build_info_json() -> String {
    json!({
        "package": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "quic": cfg!(feature = "quic"),
        "python_backend": cfg!(feature = "python-backend"),
    })
    .to_string()
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
