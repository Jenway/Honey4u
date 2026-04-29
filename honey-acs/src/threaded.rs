use crate::{AcsBackend, AcsBackendStats, AcsEvent};
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};

type PullBatch = Result<Vec<AcsEvent>, String>;
type PullReceiver = Receiver<PullBatch>;
type PendingPull = Option<PullReceiver>;

enum WorkerCommand {
    StartRound {
        round_id: usize,
        sid: String,
        proposal_input: Vec<u8>,
        response: Sender<Result<(), String>>,
    },
    PushInboundWireBatch {
        items: Vec<Vec<u8>>,
    },
    PullOutboundWireBatch {
        limit: usize,
        response: Sender<Result<Vec<AcsEvent>, String>>,
    },
    FinishRound {
        round_id: usize,
        response: Sender<Result<(), String>>,
    },
    OutboundReady {
        response: Sender<Result<bool, String>>,
    },
    Stats {
        response: Sender<Result<AcsBackendStats, String>>,
    },
    Shutdown {
        response: Sender<Result<(), String>>,
    },
}

#[derive(Default)]
struct ThreadedCommandCounts {
    start_round: AtomicUsize,
    push_inbound_wire_batch: AtomicUsize,
    pull_outbound_wire_batch: AtomicUsize,
    stats: AtomicUsize,
}

#[derive(Default)]
struct ThreadedBatchItemCounts {
    push_inbound_wire_batch_items: AtomicUsize,
    pull_outbound_wire_batch_items: AtomicUsize,
}

struct ThreadedHostState {
    processed_commands: AtomicUsize,
    worker_ident: AtomicU64,
    worker_running: AtomicBool,
    worker_error: Mutex<Option<String>>,
    command_counts: ThreadedCommandCounts,
    batch_item_counts: ThreadedBatchItemCounts,
}

impl Default for ThreadedHostState {
    fn default() -> Self {
        Self {
            processed_commands: AtomicUsize::new(0),
            worker_ident: AtomicU64::new(0),
            worker_running: AtomicBool::new(true),
            worker_error: Mutex::new(None),
            command_counts: ThreadedCommandCounts::default(),
            batch_item_counts: ThreadedBatchItemCounts::default(),
        }
    }
}

pub struct ThreadedAcsBackend<H>
where
    H: AcsBackend + Send + 'static,
{
    pid: usize,
    command_tx: Sender<WorkerCommand>,
    pending_pull: Mutex<PendingPull>,
    worker: Mutex<Option<JoinHandle<()>>>,
    state: Arc<ThreadedHostState>,
    marker: PhantomData<H>,
}

impl<H> ThreadedAcsBackend<H>
where
    H: AcsBackend + Send + 'static,
{
    pub fn new(inner: H) -> Self {
        let pid = inner.pid();
        let (command_tx, command_rx) = unbounded();
        let state = Arc::new(ThreadedHostState::default());
        let worker_state = Arc::clone(&state);
        let handle = thread::spawn(move || worker_loop(inner, command_rx, worker_state));
        Self {
            pid,
            command_tx,
            pending_pull: Mutex::new(None),
            worker: Mutex::new(Some(handle)),
            state,
            marker: PhantomData,
        }
    }

    fn lock_pending_pull(&self) -> Result<MutexGuard<'_, PendingPull>, String> {
        self.pending_pull
            .lock()
            .map_err(|_| String::from("threaded ACS host pending pull poisoned"))
    }

    fn lock_worker(&self) -> Result<MutexGuard<'_, Option<JoinHandle<()>>>, String> {
        self.worker
            .lock()
            .map_err(|_| String::from("threaded ACS host worker handle poisoned"))
    }

    fn record_processed_command(&self) {
        self.state
            .processed_commands
            .fetch_add(1, Ordering::Relaxed);
    }

    fn set_worker_error(&self, error: String) {
        if let Ok(mut slot) = self.state.worker_error.lock() {
            *slot = Some(error);
        }
    }

    fn worker_error_snapshot(&self) -> Result<Option<String>, String> {
        self.state
            .worker_error
            .lock()
            .map(|slot| slot.clone())
            .map_err(|_| String::from("threaded ACS host worker error poisoned"))
    }

    fn ensure_worker_healthy(&self) -> Result<(), String> {
        if let Some(error) = self.worker_error_snapshot()? {
            return Err(format!(
                "threaded ACS host worker failed previously: {error}"
            ));
        }
        Ok(())
    }

    fn send_sync<T>(
        &self,
        build: impl FnOnce(Sender<Result<T, String>>) -> WorkerCommand,
    ) -> Result<T, String> {
        let (response_tx, response_rx) = bounded(1);
        self.command_tx
            .send(build(response_tx))
            .map_err(|_| String::from("threaded ACS host command channel closed"))?;
        match response_rx.recv() {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                self.set_worker_error(error.clone());
                Err(error)
            }
            Err(_) => Err(String::from(
                "threaded ACS host worker stopped unexpectedly",
            )),
        }
    }
}

impl<H> AcsBackend for ThreadedAcsBackend<H>
where
    H: AcsBackend + Send + 'static,
{
    fn pid(&self) -> usize {
        self.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String> {
        self.ensure_worker_healthy()?;
        self.record_processed_command();
        self.state
            .command_counts
            .start_round
            .fetch_add(1, Ordering::Relaxed);
        self.send_sync(|response| WorkerCommand::StartRound {
            round_id,
            sid: sid.to_owned(),
            proposal_input: proposal_input.to_vec(),
            response,
        })?;
        self.ensure_worker_healthy()
    }

    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
        self.ensure_worker_healthy()?;
        self.record_processed_command();
        self.state
            .command_counts
            .push_inbound_wire_batch
            .fetch_add(1, Ordering::Relaxed);
        self.state
            .batch_item_counts
            .push_inbound_wire_batch_items
            .fetch_add(items.len(), Ordering::Relaxed);
        if items.is_empty() {
            return Ok(0);
        }
        self.command_tx
            .send(WorkerCommand::PushInboundWireBatch {
                items: items.to_vec(),
            })
            .map_err(|_| String::from("threaded ACS host command channel closed"))?;
        Ok(items.len())
    }

    fn outbound_ready(&self) -> Result<bool, String> {
        self.ensure_worker_healthy()?;
        let ready = self.send_sync(|response| WorkerCommand::OutboundReady { response })?;
        self.ensure_worker_healthy()?;
        Ok(ready)
    }

    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String> {
        self.ensure_worker_healthy()?;
        self.record_processed_command();
        self.state
            .command_counts
            .pull_outbound_wire_batch
            .fetch_add(1, Ordering::Relaxed);
        let mut pending_pull = self.lock_pending_pull()?;
        if pending_pull.is_some() {
            return Err(String::from(
                "threaded ACS host pull_outbound_wire_batch is already pending",
            ));
        }
        let (response_tx, response_rx) = bounded(1);
        self.command_tx
            .send(WorkerCommand::PullOutboundWireBatch {
                limit,
                response: response_tx,
            })
            .map_err(|_| String::from("threaded ACS host command channel closed"))?;
        *pending_pull = Some(response_rx);
        Ok(())
    }

    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsEvent>, String> {
        let pending_pull = self.lock_pending_pull()?.take().ok_or_else(|| {
            String::from("threaded ACS host pull_outbound_wire_batch was not started")
        })?;
        match pending_pull.recv() {
            Ok(Ok(events)) => {
                self.state
                    .batch_item_counts
                    .pull_outbound_wire_batch_items
                    .fetch_add(events.len(), Ordering::Relaxed);
                self.ensure_worker_healthy()?;
                Ok(events)
            }
            Ok(Err(error)) => {
                self.set_worker_error(error.clone());
                Err(error)
            }
            Err(_) => Err(String::from(
                "threaded ACS host worker stopped unexpectedly",
            )),
        }
    }

    fn finish_round(&self, round_id: usize) -> Result<(), String> {
        self.send_sync(|response| WorkerCommand::FinishRound { round_id, response })
    }

    fn stats(&self) -> Result<AcsBackendStats, String> {
        self.record_processed_command();
        self.state
            .command_counts
            .stats
            .fetch_add(1, Ordering::Relaxed);
        let mut stats = self.send_sync(|response| WorkerCommand::Stats { response })?;
        stats.worker_ident = self.state.worker_ident.load(Ordering::Relaxed);
        stats.processed_commands = self.state.processed_commands.load(Ordering::Relaxed);
        stats.bridge_queue_size = self.command_tx.len();
        stats.worker_running = self.state.worker_running.load(Ordering::Relaxed);
        stats.worker_error = self
            .state
            .worker_error
            .lock()
            .map_err(|_| String::from("threaded ACS host worker error poisoned"))?
            .clone();
        stats.start_round_calls = self
            .state
            .command_counts
            .start_round
            .load(Ordering::Relaxed);
        stats.push_inbound_wire_batch_calls = self
            .state
            .command_counts
            .push_inbound_wire_batch
            .load(Ordering::Relaxed);
        stats.push_inbound_wire_batch_items = self
            .state
            .batch_item_counts
            .push_inbound_wire_batch_items
            .load(Ordering::Relaxed);
        stats.pull_outbound_wire_batch_calls = self
            .state
            .command_counts
            .pull_outbound_wire_batch
            .load(Ordering::Relaxed);
        stats.pull_outbound_wire_batch_items = self
            .state
            .batch_item_counts
            .pull_outbound_wire_batch_items
            .load(Ordering::Relaxed);
        stats.stats_calls = self.state.command_counts.stats.load(Ordering::Relaxed);
        Ok(stats)
    }

    fn shutdown(&self) -> Result<(), String> {
        if !self.state.worker_running.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        {
            let mut pending_pull = self.lock_pending_pull()?;
            *pending_pull = None;
        }
        let result = self.send_sync(|response| WorkerCommand::Shutdown { response });
        if let Some(worker) = self.lock_worker()?.take() {
            let _ = worker.join();
        }
        result
    }
}

fn worker_loop<H>(inner: H, command_rx: Receiver<WorkerCommand>, state: Arc<ThreadedHostState>)
where
    H: AcsBackend + Send + 'static,
{
    state
        .worker_ident
        .store(thread_id_u64(thread::current().id()), Ordering::Relaxed);
    while let Ok(command) = command_rx.recv() {
        match command {
            WorkerCommand::StartRound {
                round_id,
                sid,
                proposal_input,
                response,
            } => {
                let result = inner.start_round(round_id, &sid, &proposal_input);
                update_worker_error(&state, result.as_ref().err().cloned());
                let _ = response.send(result);
            }
            WorkerCommand::PushInboundWireBatch { items } => {
                let result = inner.push_inbound_wire_batch(&items);
                update_worker_error(&state, result.err());
            }
            WorkerCommand::PullOutboundWireBatch { limit, response } => {
                let result = inner
                    .begin_pull_outbound_wire_batch(limit)
                    .and_then(|_| inner.finish_pull_outbound_wire_batch());
                update_worker_error(&state, result.as_ref().err().cloned());
                let _ = response.send(result);
            }
            WorkerCommand::FinishRound { round_id, response } => {
                let result = inner.finish_round(round_id);
                update_worker_error(&state, result.as_ref().err().cloned());
                let _ = response.send(result);
            }
            WorkerCommand::OutboundReady { response } => {
                let result = inner.outbound_ready();
                update_worker_error(&state, result.as_ref().err().cloned());
                let _ = response.send(result);
            }
            WorkerCommand::Stats { response } => {
                let result = inner.stats();
                update_worker_error(&state, result.as_ref().err().cloned());
                let _ = response.send(result);
            }
            WorkerCommand::Shutdown { response } => {
                let result = inner.shutdown();
                update_worker_error(&state, result.as_ref().err().cloned());
                let _ = response.send(result);
                break;
            }
        }
    }
    state.worker_running.store(false, Ordering::Relaxed);
}

fn update_worker_error(state: &Arc<ThreadedHostState>, error: Option<String>) {
    if let Some(error) = error
        && let Ok(mut slot) = state.worker_error.lock()
    {
        *slot = Some(error);
    }
}

fn thread_id_u64(thread_id: thread::ThreadId) -> u64 {
    let rendered = format!("{thread_id:?}");
    rendered
        .strip_prefix("ThreadId(")
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|digits| digits.parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct AsyncFailBackend {
        failed_inbound: AtomicBool,
    }

    impl AsyncFailBackend {
        fn new() -> Self {
            Self {
                failed_inbound: AtomicBool::new(false),
            }
        }
    }

    impl AcsBackend for AsyncFailBackend {
        fn pid(&self) -> usize {
            0
        }

        fn start_round(
            &self,
            _round_id: usize,
            _sid: &str,
            _proposal_input: &[u8],
        ) -> Result<(), String> {
            Ok(())
        }

        fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
            if !items.is_empty() {
                self.failed_inbound.store(true, Ordering::Relaxed);
                return Err(String::from("synthetic inbound failure"));
            }
            Ok(0)
        }

        fn outbound_ready(&self) -> Result<bool, String> {
            Ok(false)
        }

        fn begin_pull_outbound_wire_batch(&self, _limit: usize) -> Result<(), String> {
            Ok(())
        }

        fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsEvent>, String> {
            Ok(Vec::new())
        }

        fn finish_round(&self, _round_id: usize) -> Result<(), String> {
            Ok(())
        }

        fn stats(&self) -> Result<AcsBackendStats, String> {
            Ok(AcsBackendStats {
                worker_ident: 0,
                rounds_started: 0,
                rounds_finished: 0,
                processed_commands: 0,
                bridge_queue_size: 0,
                worker_running: true,
                worker_error: None,
                start_round_calls: 0,
                push_inbound_wire_batch_calls: 0,
                push_inbound_wire_batch_items: 0,
                pull_outbound_wire_batch_calls: 0,
                pull_outbound_wire_batch_items: 0,
                stats_calls: 0,
            })
        }

        fn shutdown(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn async_inbound_failure_surfaces_on_next_sync_call() {
        let backend = ThreadedAcsBackend::new(AsyncFailBackend::new());
        backend
            .push_inbound_wire_batch(&[vec![1, 2, 3]])
            .expect("async push should still enqueue");

        let error = backend
            .outbound_ready()
            .expect_err("next sync call should surface stored worker error");
        assert!(error.contains("synthetic inbound failure"));

        backend.shutdown().expect("shutdown should still succeed");
    }

    #[test]
    fn shutdown_still_works_after_async_inbound_failure() {
        let backend = ThreadedAcsBackend::new(AsyncFailBackend::new());
        backend
            .push_inbound_wire_batch(&[vec![9]])
            .expect("async push should still enqueue");

        backend
            .shutdown()
            .expect("shutdown must bypass prior worker error state");
    }
}
