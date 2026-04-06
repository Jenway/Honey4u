use super::*;
use crate::py_host::RustDrivenAcsHost;

impl RustDrivenAcsHost for HbNodeRuntime {
    fn pid(&self) -> usize {
        self.acs_host.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, local_input: &[u8]) -> Result<(), String> {
        self.acs_host.start_round(round_id, sid, local_input)
    }

    fn deliver_decoded(
        &self,
        sender: usize,
        round_id: usize,
        channel: &str,
        instance_id: Option<usize>,
        message: &Py<PyAny>,
    ) -> Result<(), String> {
        self.acs_host
            .deliver_decoded(sender, round_id, channel, instance_id, message)
    }

    fn drain_events(&self, limit: usize) -> Result<Vec<PyAcsEvent>, String> {
        self.acs_host.drain_events(limit)
    }

    fn stats(&self) -> Result<PyAcsHostStats, String> {
        self.acs_host.stats()
    }

    fn shutdown(&self) -> Result<(), String> {
        self.acs_host.shutdown()
    }
}

impl HbWorkerProcess {
    pub(crate) fn spawn(args: HbWorkerSpawnArgs<'_>) -> Result<Self, String> {
        let mut child = Command::new(args.binary_path)
            .arg("hb-worker")
            .arg("--pid")
            .arg(args.pid.to_string())
            .arg("--nodes")
            .arg(args.nodes.to_string())
            .arg("--faulty")
            .arg(args.faulty.to_string())
            .arg("--acs-protocol")
            .arg(args.acs_protocol.as_str())
            .arg("--acs-crypto-json")
            .arg(args.acs_crypto_json)
            .arg("--hb-crypto-json")
            .arg(args.hb_crypto_json)
            .arg("--config-json")
            .arg(args.config_json)
            .arg("--ipc-mode")
            .arg(HbWorkerIpcMode::Binary.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|err| format!("failed to spawn hb-worker pid={}: {err}", args.pid))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("failed to open hb-worker stdin for pid={}", args.pid))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("failed to open hb-worker stdout for pid={}", args.pid))?;

        Ok(Self {
            pid: args.pid,
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn request(&mut self, request: HbWorkerRequest) -> Result<HbWorkerResponse, String> {
        write_bincode_frame(&mut self.stdin, &request)
            .map_err(|err| format!("hb-worker pid={} request failed: {err}", self.pid))?;

        let response = read_bincode_frame::<_, Result<HbWorkerResponse, String>>(&mut self.stdout)
            .map_err(|err| format!("hb-worker pid={} response read failed: {err}", self.pid))?;
        let Some(response) = response else {
            let status = self
                .child
                .wait()
                .map_err(|err| format!("hb-worker pid={} wait failed: {err}", self.pid))?;
            return Err(format!(
                "hb-worker pid={} exited before responding: {}",
                self.pid, status
            ));
        };
        response.map_err(|err| format!("hb-worker pid={} returned error: {err}", self.pid))
    }

    pub(crate) fn start_round(
        &mut self,
        round_id: usize,
        sid: &str,
        local_input: &[u8],
    ) -> Result<(), String> {
        let _ = self.request(HbWorkerRequest::StartRound {
            round_id,
            sid: sid.to_string(),
            local_input: local_input.to_vec(),
        })?;
        Ok(())
    }

    pub(crate) fn deliver_batch(&mut self, payloads: &[Vec<u8>]) -> Result<(), String> {
        if payloads.is_empty() {
            return Ok(());
        }

        let _ = self.request(HbWorkerRequest::DeliverBatch {
            payloads: payloads.to_vec(),
        })?;
        Ok(())
    }

    pub(crate) fn drain_events(&mut self, limit: usize) -> Result<Vec<HbWorkerEvent>, String> {
        match self.request(HbWorkerRequest::DrainEvents { limit })? {
            HbWorkerResponse::Events(events) => {
                Ok(events.into_iter().map(worker_event_from_payload).collect())
            }
            _ => Err(format!(
                "hb-worker pid={} returned non-events response",
                self.pid
            )),
        }
    }

    pub(crate) fn stats(&mut self) -> Result<PyAcsHostStats, String> {
        match self.request(HbWorkerRequest::Stats)? {
            HbWorkerResponse::Stats(stats) => Ok(stats_from_payload(stats)),
            _ => Err(format!(
                "hb-worker pid={} returned non-stats response",
                self.pid
            )),
        }
    }

    pub(crate) fn tpke_local_bundle(
        &mut self,
        selected_batches: &[Vec<u8>],
    ) -> Result<(HbShareBundle, f64), String> {
        match self.request(HbWorkerRequest::TpkeLocalBundle {
            selected_batches: selected_batches.to_vec(),
        })? {
            HbWorkerResponse::TpkeLocalBundle {
                bundle,
                elapsed_seconds,
            } => Ok((bundle, elapsed_seconds)),
            _ => Err(format!(
                "hb-worker pid={} returned non-tpke response",
                self.pid
            )),
        }
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), String> {
        if let Some(status) = self
            .child
            .try_wait()
            .map_err(|err| format!("hb-worker pid={} try_wait failed: {err}", self.pid))?
        {
            return if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "hb-worker pid={} exited unexpectedly: {}",
                    self.pid, status
                ))
            };
        }

        let shutdown_result = self.request(HbWorkerRequest::Shutdown);
        let status = self
            .child
            .wait()
            .map_err(|err| format!("hb-worker pid={} wait failed: {err}", self.pid))?;
        match shutdown_result {
            Ok(_) if status.success() => Ok(()),
            Ok(_) => Err(format!(
                "hb-worker pid={} exited with non-zero status after shutdown: {}",
                self.pid, status
            )),
            Err(err) => Err(err),
        }
    }
}

pub(crate) fn run_hb_worker(args: HbWorkerArgs) -> Result<(), String> {
    let acs_host = PyAcsHost::new(
        args.acs_protocol,
        args.pid,
        args.nodes,
        args.faulty,
        &args.acs_crypto_json,
        &args.config_json,
    )?;
    let (public_key, private_share) = parse_honeybadger_crypto_payload(&args.hb_crypto_json)?;
    let runtime = HbNodeRuntime::new(acs_host, private_share);

    let shutdown_requested = match args.ipc_mode {
        HbWorkerIpcMode::Json => run_hb_worker_json(&runtime, &public_key)?,
        HbWorkerIpcMode::Binary => run_hb_worker_binary(&runtime, &public_key)?,
    };

    if !shutdown_requested {
        let _ = runtime.shutdown();
    }

    Ok(())
}

fn run_hb_worker_json(
    runtime: &HbNodeRuntime,
    public_key: &HbPkePublicParams,
) -> Result<bool, String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut shutdown_requested = false;

    for line in BufReader::new(stdin.lock()).lines() {
        let line = line.map_err(|err| err.to_string())?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match handle_hb_worker_command(runtime, public_key, &line) {
            Ok((payload, should_shutdown)) => {
                shutdown_requested = should_shutdown;
                payload
            }
            Err(err) => json!({"ok": false, "error": err}),
        };

        let rendered = serde_json::to_string(&response).map_err(|err| err.to_string())?;
        writeln!(stdout, "{rendered}").map_err(|err| err.to_string())?;
        stdout.flush().map_err(|err| err.to_string())?;

        if shutdown_requested {
            break;
        }
    }

    Ok(shutdown_requested)
}

fn run_hb_worker_binary(
    runtime: &HbNodeRuntime,
    public_key: &HbPkePublicParams,
) -> Result<bool, String> {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut shutdown_requested = false;

    while let Some(request) = read_bincode_frame::<_, HbWorkerRequest>(&mut stdin)? {
        let response = handle_hb_worker_request(runtime, public_key, request);
        let should_shutdown = matches!(&response, Ok((_payload, true)));
        write_bincode_frame(&mut stdout, &response)?;
        if should_shutdown {
            shutdown_requested = true;
            break;
        }
    }

    Ok(shutdown_requested)
}

fn handle_hb_worker_command(
    runtime: &HbNodeRuntime,
    public_key: &HbPkePublicParams,
    line: &str,
) -> Result<(Value, bool), String> {
    let command = serde_json::from_str::<Value>(line).map_err(|err| err.to_string())?;
    let kind = json_string_field(&command, "kind")?;

    match kind {
        "stats" => {
            let stats = runtime.stats()?;
            Ok((
                json!({
                    "ok": true,
                    "stats": {
                        "pid": runtime.pid(),
                        "worker_ident": stats.worker_ident,
                        "rounds_started": stats.rounds_started,
                        "rounds_finished": stats.rounds_finished,
                        "processed_commands": stats.processed_commands,
                        "bridge_queue_size": stats.bridge_queue_size,
                        "worker_running": stats.worker_running,
                        "worker_error": stats.worker_error,
                    }
                }),
                false,
            ))
        }
        "start_round" => {
            let round_id = json_usize_field(&command, "round_id")?;
            let sid = json_string_field(&command, "sid")?;
            let local_input = decode_hex(json_string_field(&command, "local_input_hex")?)?;
            runtime.start_round(round_id, sid, &local_input)?;
            Ok((json!({"ok": true}), false))
        }
        "deliver" => {
            let payload = decode_hex(json_string_field(&command, "payload_hex")?)?;
            runtime.acs_host.deliver_raw(&payload)?;
            Ok((json!({"ok": true}), false))
        }
        "deliver_batch" => {
            let payloads = json_string_list_field(&command, "payloads_hex")?
                .into_iter()
                .map(|payload| decode_hex(&payload))
                .collect::<Result<Vec<_>, _>>()?;
            runtime.acs_host.deliver_raw_batch(&payloads)?;
            Ok((json!({"ok": true}), false))
        }
        "drain_events" => {
            let limit = command.get("limit").and_then(Value::as_u64).unwrap_or(128) as usize;
            let rendered_events = runtime
                .drain_events(limit)?
                .into_iter()
                .map(|event| match event {
                    PyAcsEvent::Send {
                        round_id,
                        recipient,
                        channel,
                        instance_id,
                        message,
                    } => Ok(json!({
                        "kind": "send",
                        "round_id": round_id,
                        "recipient": recipient,
                        "payload_hex": hex_encode(&encode_protocol_envelope(
                            runtime.pid(),
                            round_id,
                            &channel,
                            instance_id,
                            &message,
                        )?),
                    })),
                    PyAcsEvent::Decision { round_id, values } => Ok(json!({
                        "kind": "decision",
                        "round_id": round_id,
                        "values_hex": values
                            .into_iter()
                            .map(|value| value.map(|bytes| hex_encode(&bytes)))
                            .collect::<Vec<_>>(),
                    })),
                    PyAcsEvent::Failure {
                        round_id,
                        error,
                        exception_type,
                    } => Ok(json!({
                        "kind": "failure",
                        "round_id": round_id,
                        "error": error,
                        "exception_type": exception_type,
                    })),
                    PyAcsEvent::Carryovers { round_id } => Ok(json!({
                        "kind": "carryovers",
                        "round_id": round_id,
                    })),
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok((json!({"ok": true, "events": rendered_events}), false))
        }
        "tpke_local_bundle" => {
            let selected_batches = json_string_list_field(&command, "selected_batches_hex")?
                .into_iter()
                .map(|payload| decode_hex(&payload))
                .collect::<Result<Vec<_>, _>>()?;
            let start = Instant::now();
            let decryptor = HbBatchDecryptor::new(public_key.clone(), selected_batches)?;
            let bundle = decryptor.local_shares(runtime.tpke_private_share())?;
            Ok((
                json!({
                    "ok": true,
                    "bundle_hex": bundle.into_iter().map(|share| hex_encode(&share)).collect::<Vec<_>>(),
                    "elapsed_seconds": start.elapsed().as_secs_f64(),
                }),
                false,
            ))
        }
        "shutdown" => {
            runtime.shutdown()?;
            Ok((json!({"ok": true}), true))
        }
        _ => Err(format!("unknown hb-worker command kind: {kind}")),
    }
}

fn handle_hb_worker_request(
    runtime: &HbNodeRuntime,
    public_key: &HbPkePublicParams,
    request: HbWorkerRequest,
) -> Result<(HbWorkerResponse, bool), String> {
    match request {
        HbWorkerRequest::Stats => {
            let stats = runtime.stats()?;
            Ok((
                HbWorkerResponse::Stats(stats_payload_from_stats(runtime.pid(), stats)),
                false,
            ))
        }
        HbWorkerRequest::StartRound {
            round_id,
            sid,
            local_input,
        } => {
            runtime.start_round(round_id, &sid, &local_input)?;
            Ok((HbWorkerResponse::Ack, false))
        }
        HbWorkerRequest::DeliverBatch { payloads } => {
            runtime.acs_host.deliver_raw_batch(&payloads)?;
            Ok((HbWorkerResponse::Ack, false))
        }
        HbWorkerRequest::DrainEvents { limit } => {
            let events = runtime
                .drain_events(limit)?
                .into_iter()
                .map(|event| match event {
                    PyAcsEvent::Send {
                        round_id,
                        recipient,
                        channel,
                        instance_id,
                        message,
                    } => Ok(HbWorkerEventPayload::Send {
                        round_id,
                        recipient,
                        payload: encode_protocol_envelope(
                            runtime.pid(),
                            round_id,
                            &channel,
                            instance_id,
                            &message,
                        )?,
                    }),
                    PyAcsEvent::Decision { round_id, values } => {
                        Ok(HbWorkerEventPayload::Decision { round_id, values })
                    }
                    PyAcsEvent::Failure {
                        round_id,
                        error,
                        exception_type,
                    } => Ok(HbWorkerEventPayload::Failure {
                        round_id,
                        error,
                        exception_type,
                    }),
                    PyAcsEvent::Carryovers { round_id } => {
                        Ok(HbWorkerEventPayload::Carryovers { round_id })
                    }
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok((HbWorkerResponse::Events(events), false))
        }
        HbWorkerRequest::TpkeLocalBundle { selected_batches } => {
            let start = Instant::now();
            let decryptor = HbBatchDecryptor::new(public_key.clone(), selected_batches)?;
            let bundle = decryptor
                .local_shares(runtime.tpke_private_share())?
                .into_iter()
                .map(Some)
                .collect::<Vec<_>>();
            Ok((
                HbWorkerResponse::TpkeLocalBundle {
                    bundle,
                    elapsed_seconds: start.elapsed().as_secs_f64(),
                },
                false,
            ))
        }
        HbWorkerRequest::Shutdown => {
            runtime.shutdown()?;
            Ok((HbWorkerResponse::Ack, true))
        }
    }
}
