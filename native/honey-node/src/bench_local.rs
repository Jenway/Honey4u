use super::*;

pub(crate) fn run_rust_hosted_node(args: RunNodeArgs) -> Result<(), String> {
    Python::attach(|py| -> PyResult<()> {
        prepend_python_paths(py)?;

        let rust_host = PyModule::import(py, "honey.host.rust_host")?;
        let result = rust_host.getattr("run_protocol_node")?.call1((
            args.protocol.as_str(),
            args.sid,
            args.pid,
            args.nodes,
            args.faulty,
            args.addresses_json,
            args.crypto_json,
            args.config_json,
            args.transactions_per_node,
            args.tx_input,
            args.start_at_ms,
        ))?;

        let json = PyModule::import(py, "json")?;
        let rendered = json
            .getattr("dumps")?
            .call1((result,))?
            .extract::<String>()?;
        write_output(args.result_path.as_deref(), &rendered)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok(())
    })
    .map_err(|err| err.to_string())
}

pub(crate) fn run_bench_local(args: BenchLocalArgs) -> Result<(), String> {
    if args.transport_backend != "tcp" {
        return Err(format!(
            "unsupported transport backend for rust-hosted benchmark: {}",
            args.transport_backend
        ));
    }
    if args.round_timeout <= 0.0 {
        return Err(String::from("--round-timeout must be > 0"));
    }

    let _ = args.batch_size;
    let _ = &args.log_level;

    let addresses = allocate_loopback_addresses(args.nodes)?;
    let addresses_json = serde_json::to_string(&addresses).map_err(|err| err.to_string())?;
    let crypto_payloads = serialize_crypto_payloads(args.protocol, args.nodes, args.faulty)?;
    let result_dir = build_result_dir(
        &format!("{}-rust-hosted", args.protocol.as_str()),
        &args.sid,
    )?;
    let start_at_ms = current_time_millis()?
        .checked_add(5_000)
        .ok_or_else(|| String::from("start time overflow"))?;
    let binary = std::env::current_exe().map_err(|err| err.to_string())?;
    let mut processes = Vec::new();

    for (pid, crypto_json) in crypto_payloads.into_iter().enumerate() {
        let result_path = result_dir.join(format!("node-{pid}.json"));
        let stdout_path = result_dir.join(format!("node-{pid}.out.log"));
        let stderr_path = result_dir.join(format!("node-{pid}.err.log"));
        let stdout_handle = File::create(&stdout_path).map_err(|err| err.to_string())?;
        let stderr_handle = File::create(&stderr_path).map_err(|err| err.to_string())?;

        let child = Command::new(&binary)
            .arg("run-node")
            .arg("--protocol")
            .arg(args.protocol.as_str())
            .arg("--pid")
            .arg(pid.to_string())
            .arg("--nodes")
            .arg(args.nodes.to_string())
            .arg("--faulty")
            .arg(args.faulty.to_string())
            .arg("--rounds")
            .arg(args.rounds.to_string())
            .arg("--sid")
            .arg(&args.sid)
            .arg("--addresses-json")
            .arg(&addresses_json)
            .arg("--crypto-json")
            .arg(&crypto_json)
            .arg("--config-json")
            .arg(&args.config_json)
            .arg("--transactions-per-node")
            .arg(args.transactions_per_node.to_string())
            .arg("--tx-input")
            .arg(&args.tx_input)
            .arg("--start-at-ms")
            .arg(start_at_ms.to_string())
            .arg("--result-path")
            .arg(&result_path)
            .stdout(Stdio::from(stdout_handle))
            .stderr(Stdio::from(stderr_handle))
            .spawn()
            .map_err(|err| err.to_string())?;

        processes.push(SpawnedNode {
            pid,
            child,
            result_path,
            stderr_path,
        });
    }

    let deadline = Instant::now() + Duration::from_secs_f64(args.global_timeout);
    while Instant::now() < deadline {
        if processes.iter().all(|process| process.result_path.exists()) {
            break;
        }

        let mut observed_failure = false;
        for process in &mut processes {
            if let Some(status) = process.child.try_wait().map_err(|err| err.to_string())?
                && !status.success()
            {
                observed_failure = true;
                break;
            }
        }
        if observed_failure {
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    let all_results_ready = processes.iter().all(|process| process.result_path.exists());
    let mut errors = Vec::new();
    let mut results: Vec<Option<Value>> = (0..args.nodes).map(|_| None).collect();

    for process in &mut processes {
        let status = match process.child.try_wait().map_err(|err| err.to_string())? {
            Some(status) => status,
            None if all_results_ready => process.child.wait().map_err(|err| err.to_string())?,
            None => {
                let _ = process.child.kill();
                process.child.wait().map_err(|err| err.to_string())?
            }
        };

        if !status.success() {
            let stderr = read_log_file(&process.stderr_path);
            errors.push(format!(
                "pid={}: returncode={}: {}",
                process.pid,
                status.code().unwrap_or(-1),
                stderr.trim()
            ));
            continue;
        }

        if !process.result_path.exists() {
            let stderr = read_log_file(&process.stderr_path);
            errors.push(format!(
                "pid={}: missing result file: {}",
                process.pid,
                stderr.trim()
            ));
            continue;
        }

        let content = fs::read_to_string(&process.result_path).map_err(|err| err.to_string())?;
        let parsed = serde_json::from_str::<Value>(&content).map_err(|err| err.to_string())?;
        results[process.pid] = Some(parsed);
    }

    if !all_results_ready && errors.is_empty() {
        errors.push(format!(
            "benchmark timed out after {:.3}s before all node results were written",
            args.global_timeout
        ));
    }

    let rendered = if errors.is_empty() {
        let flattened: Vec<Value> = results
            .into_iter()
            .enumerate()
            .map(|(pid, value)| value.ok_or_else(|| format!("pid={pid}: missing decoded result")))
            .collect::<Result<_, _>>()?;
        serde_json::to_string(&flattened).map_err(|err| err.to_string())?
    } else {
        let _ = fs::remove_dir_all(&result_dir);
        return Err(format!(
            "Rust-hosted benchmark failed: {}",
            errors.join("; ")
        ));
    };

    if let Some(result_path) = args.result_path {
        write_output(Some(&result_path), &rendered).map_err(|err| err.to_string())?;
    } else {
        write_output(None, &rendered).map_err(|err| err.to_string())?;
    }

    let _ = fs::remove_dir_all(&result_dir);
    Ok(())
}
