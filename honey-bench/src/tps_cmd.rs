//! `honey-bench tps` subcommand — full-featured single/sweep benchmark CLI.
//!
//! Mirrors `benchmarks/cli/tps.py` but entirely in Rust.

use std::io::Write;

fn parse_comma_usize(raw: &str) -> Result<Vec<usize>, String> {
    raw.split(',')
        .map(|s| {
            s.trim()
                .parse::<usize>()
                .map_err(|e| format!("invalid integer in list: {e}"))
        })
        .collect()
}

fn print_help() {
    eprintln!("honey-bench tps [OPTIONS]");
    eprintln!();
    eprintln!("Run a TPS/throughput benchmark and produce a structured JSON result.");
    eprintln!();
    eprintln!("== Core ==");
    eprintln!("  --protocol P           hb or dumbo [default: dumbo]");
    eprintln!("  --backend B            rust_fin, rust_dumbo, python [default: rust_fin]");
    eprintln!("  --transport T          tcp or quic [default: tcp]");
    eprintln!();
    eprintln!("== Pool reuse ==");
    eprintln!("  --enable-pool-reuse    enable broadcast pool reuse");
    eprintln!("  --pool-grace-ms MS     grace period for carry-over PRBC outputs [default: 200]");
    eprintln!("  --pool-reuse-limit-per-round N  max reusable proposals per round [default: 4]");
    eprintln!(
        "  --pool-expire-rounds N          expire entries after this many rounds [default: 10]"
    );
    eprintln!("  --pool-mempool-max N            max mempool entries [default: 1024]");
    eprintln!();
    eprintln!("== Network faults ==");
    eprintln!("  --network-fixed-delay-ms N   inject fixed send delay in ms");
    eprintln!("  --network-jitter-ms N        inject uniform random jitter up to N ms per frame");
    eprintln!("  --network-seed N             deterministic seed for delay/jitter injection");
    eprintln!("  --slow-honest-pids PIDs      comma-separated honest node ids for extra delay");
    eprintln!("  --slow-honest-extra-delay-ms N  extra delay for slow-honest nodes");
    eprintln!();
    eprintln!("== Byzantine ==");
    eprintln!("  --byzantine-pids PIDs        comma-separated node ids for byzantine behavior");
    eprintln!("  --byzantine-behavior BEH     silent or invalid_fetch_response");
    eprintln!();
    eprintln!("== Output ==");
    eprintln!("  --sid S              benchmark session id");
    eprintln!("  --output-json PATH   write JSON result to file");
    eprintln!("  --json               output JSON to stdout only");
    eprintln!("  --fail-on-divergence exit with error if chain digests differ");
    eprintln!("  --sweep-batches B    comma-separated batch sizes for sweep mode");
    eprintln!();
    eprintln!("== Help ==");
    eprintln!("  --help, -h           show this message");
}

pub fn cmd_tps(mut argv: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut nodes: Option<usize> = None;
    let mut faulty: Option<usize> = None;
    let mut batch_size: Option<usize> = None;
    let mut sweep_batches: Option<Vec<usize>> = None;
    let mut rounds: Option<usize> = None;
    let mut warmup_rounds: usize = 0;
    let mut global_timeout: Option<f64> = None;
    let mut protocol: &str = "dumbo";
    let mut backend: &str = "rust_fin";
    let mut reuse: bool = false;
    let mut pool_grace_ms: u64 = 200;
    let mut pool_reuse_limit: usize = 4;
    let mut pool_expire_rounds: u32 = 10;
    let mut pool_mempool_max: usize = 1024;
    let mut network_fixed_delay_ms: Option<u64> = None;
    let mut network_jitter_ms: Option<u64> = None;
    let mut network_seed: Option<u64> = None;
    let mut slow_honest_pids_str: Option<String> = None;
    let mut slow_honest_extra_delay_ms: Option<u64> = None;
    let mut byzantine_pids_str: Option<String> = None;
    let mut byzantine_behavior: Option<String> = None;
    let mut sid: Option<String> = None;
    let mut output_json: Option<String> = None;
    let mut json_mode: bool = false;
    let mut fail_on_divergence: bool = false;
    let mut ledger_dir: Option<String> = None;
    let mut transport: &str = "tcp";

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--nodes" => nodes = Some(argv.next().ok_or("--nodes requires a value")?.parse()?),
            "--faulty" => faulty = Some(argv.next().ok_or("--faulty requires a value")?.parse()?),
            "--batch-size" => {
                batch_size = Some(
                    argv.next()
                        .ok_or("--batch-size requires a value")?
                        .parse()?,
                )
            }
            "--sweep-batches" => {
                let raw = argv
                    .next()
                    .ok_or("--sweep-batches requires a comma-separated value")?;
                sweep_batches = Some(parse_comma_usize(&raw)?);
            }
            "--rounds" => rounds = Some(argv.next().ok_or("--rounds requires a value")?.parse()?),
            "--warmup-rounds" => {
                warmup_rounds = argv
                    .next()
                    .ok_or("--warmup-rounds requires a value")?
                    .parse()?
            }
            "--global-timeout" => {
                global_timeout = Some(
                    argv.next()
                        .ok_or("--global-timeout requires a value")?
                        .parse()?,
                )
            }
            "--protocol" => protocol = argv.next().ok_or("--protocol requires a value")?.leak(),
            "--backend" => backend = argv.next().ok_or("--backend requires a value")?.leak(),
            "--transport" => transport = argv.next().ok_or("--transport requires a value")?.leak(),
            "--enable-pool-reuse" => reuse = true,
            "--pool-grace-ms" => {
                pool_grace_ms = argv
                    .next()
                    .ok_or("--pool-grace-ms requires a value")?
                    .parse()?
            }
            "--pool-reuse-limit-per-round" => {
                pool_reuse_limit = argv
                    .next()
                    .ok_or("--pool-reuse-limit-per-round requires a value")?
                    .parse()?
            }
            "--pool-expire-rounds" => {
                pool_expire_rounds = argv
                    .next()
                    .ok_or("--pool-expire-rounds requires a value")?
                    .parse()?
            }
            "--pool-mempool-max" => {
                pool_mempool_max = argv
                    .next()
                    .ok_or("--pool-mempool-max requires a value")?
                    .parse()?
            }
            "--network-fixed-delay-ms" => {
                network_fixed_delay_ms = Some(
                    argv.next()
                        .ok_or("--network-fixed-delay-ms requires a value")?
                        .parse()?,
                )
            }
            "--network-jitter-ms" => {
                network_jitter_ms = Some(
                    argv.next()
                        .ok_or("--network-jitter-ms requires a value")?
                        .parse()?,
                )
            }
            "--network-seed" => {
                network_seed = Some(
                    argv.next()
                        .ok_or("--network-seed requires a value")?
                        .parse()?,
                )
            }
            "--slow-honest-pids" => {
                slow_honest_pids_str =
                    Some(argv.next().ok_or("--slow-honest-pids requires a value")?)
            }
            "--slow-honest-extra-delay-ms" => {
                slow_honest_extra_delay_ms = Some(
                    argv.next()
                        .ok_or("--slow-honest-extra-delay-ms requires a value")?
                        .parse()?,
                )
            }
            "--byzantine-pids" => {
                byzantine_pids_str = Some(argv.next().ok_or("--byzantine-pids requires a value")?)
            }
            "--byzantine-behavior" => {
                byzantine_behavior =
                    Some(argv.next().ok_or("--byzantine-behavior requires a value")?)
            }
            "--sid" => sid = Some(argv.next().ok_or("--sid requires a value")?),
            "--output-json" => {
                output_json = Some(argv.next().ok_or("--output-json requires a value")?)
            }
            "--json" => json_mode = true,
            "--fail-on-divergence" => fail_on_divergence = true,
            "--ledger-dir" => {
                ledger_dir = Some(argv.next().ok_or("--ledger-dir requires a value")?)
            }
            a if a.starts_with('-') => return Err(format!("unknown tps flag: {a}").into()),
            _ => return Err(format!("unexpected positional argument: {arg}").into()),
        }
    }

    let nodes = nodes.unwrap_or(4);
    let faulty = faulty.unwrap_or_else(|| (nodes - 1) / 3);
    let global_timeout = global_timeout.unwrap_or(30.0);

    // Build network-faults config
    let mut nf_parts: Vec<String> = Vec::new();
    nf_parts.push("\"enabled\":false".to_owned());
    if network_fixed_delay_ms.is_some()
        || network_jitter_ms.is_some()
        || slow_honest_pids_str.is_some()
    {
        nf_parts[0] = "\"enabled\":true".to_owned();
    }
    if let Some(seed) = network_seed {
        nf_parts.push(format!("\"seed\":{seed}"));
    }
    if let Some(delay) = network_fixed_delay_ms {
        nf_parts.push(format!("\"fixed_delay_ms\":{delay}"));
    }
    if let Some(jitter) = network_jitter_ms {
        nf_parts.push(format!("\"jitter_ms\":{jitter}"));
    }
    if let Some(ref pids_str) = slow_honest_pids_str
        && let Some(delay) = slow_honest_extra_delay_ms
    {
        let pids: Vec<usize> = parse_comma_usize(pids_str)?;
        let pids_json: Vec<String> = pids.iter().map(|p| p.to_string()).collect();
        nf_parts.push(format!(
            "\"slow_honest\":{{\"pids\":[{pids}],\"extra_delay_ms\":{delay}}}",
            pids = pids_json.join(",")
        ));
    }
    let nf_config = format!("{{{}}}", nf_parts.join(","));

    // Build byzantine config
    let byz_cfg = if let Some(ref pids_str) = byzantine_pids_str {
        let pids: Vec<usize> = parse_comma_usize(pids_str)?;
        let behavior = byzantine_behavior
            .clone()
            .unwrap_or_else(|| "silent".to_owned());
        let byz_entries: Vec<String> = pids
            .iter()
            .map(|pid| format!(r#"{{"pid":{pid},"behavior":"{behavior}"}}"#))
            .collect();
        format!("[{}]", byz_entries.join(","))
    } else {
        "[]".to_owned()
    };

    let sip_prefix = sid
        .clone()
        .unwrap_or_else(|| format!("tps:{protocol}:{backend}:n{nodes}"));

    let batches: Vec<usize> = if let Some(ref sweeps) = sweep_batches {
        sweeps.clone()
    } else {
        vec![batch_size.unwrap_or(1)]
    };

    let mut all_results: Vec<serde_json::Value> = Vec::with_capacity(batches.len());

    for &bs in &batches {
        let run_sid = if batches.len() > 1 {
            format!("{sip_prefix}:b{bs}")
        } else {
            sip_prefix.clone()
        };

        let config_json = format!(
            r#"{{"acs_host_backend":"{backend}","transport":"{transport}","enable_broadcast_pool_reuse":{reuse},"enable_pool_reference_proposals":{reuse},"enable_pool_fetch_fallback":{reuse},"pool_grace_ms":{pool_grace_ms},"pool_reuse_limit_per_round":{pool_reuse_limit},"pool_expire_rounds":{pool_expire_rounds},"pool_mempool_max":{pool_mempool_max},"network_faults":{nf_config},"byzantine_nodes":{byz_cfg}}}"#
        );

        let node_binary = crate::resolve_node_binary()?;
        let args = crate::BenchDumboArgs {
            sid: run_sid.clone(),
            acs_backend: honey_acs::AcsBackendKind::parse(backend)?,
            nodes,
            faulty,
            rounds: rounds.unwrap_or(1),
            batch_size: bs,
            global_timeout: (global_timeout + 10.0).max(global_timeout * 1.3),
            config_json,
            result_path: None,
            ledger_dir: ledger_dir.clone(),
            tx_json: None,
        };

        let result_json_str = crate::run_drive_dumbo_multiprocess(&args, &node_binary)?;

        let raw: serde_json::Value =
            serde_json::from_str(&result_json_str).map_err(|e| format!("parse result: {e}"))?;

        let tps_result = crate::tps::build_tps_result(&raw, warmup_rounds, backend);
        let tps_result = crate::tps::TpsResult {
            batch_size: bs,
            global_timeout,
            enable_pool_reuse: reuse,
            pool_grace_ms,
            sid: run_sid,
            ..tps_result
        };

        let output = crate::tps::tps_result_to_json(&tps_result);
        all_results.push(output);
    }

    let final_output = if all_results.len() == 1 {
        all_results.pop().unwrap()
    } else {
        serde_json::json!({
            "sweep": true,
            "batch_sizes": batches,
            "results": all_results,
        })
    };

    let rendered = serde_json::to_string_pretty(&final_output)?;

    if let Some(ref path) = output_json {
        std::fs::write(path, &rendered).map_err(|e| format!("write {path}: {e}"))?;
        if !json_mode {
            eprintln!("[tps] wrote {path}");
        }
    }

    if json_mode {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(rendered.as_bytes())?;
        handle.write_all(b"\n")?;
    } else if output_json.is_none() {
        eprintln!("[tps] done — use --output-json or --json to capture output");
    }

    if fail_on_divergence {
        for result in &all_results {
            let Some(consistency) = result.get("consistency") else {
                continue;
            };
            if !consistency
                .get("all_nodes_agree")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
            {
                return Err("chain digests diverged (see consistency field)".into());
            }
        }
    }

    Ok(())
}
