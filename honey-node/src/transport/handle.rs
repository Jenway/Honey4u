use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

#[derive(Clone, Copy, Debug, Default)]
pub struct TransportSnapshot {
    pub pending_inbound: usize,
    pub pending_outbound: usize,
    pub wakeup_seq: u64,
}

#[derive(Debug)]
pub struct WakeupCounter {
    seq: AtomicU64,
    waiter: Mutex<Option<thread::Thread>>,
}

impl WakeupCounter {
    pub fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            waiter: Mutex::new(None),
        }
    }

    pub fn notify(&self) {
        self.seq.fetch_add(1, Ordering::Relaxed);
        let maybe_thread = self.waiter.lock().ok().and_then(|g| g.clone());
        if let Some(t) = maybe_thread {
            t.unpark();
        }
    }

    pub fn snapshot(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    pub fn register(&self, t: thread::Thread) {
        if let Ok(mut g) = self.waiter.lock() {
            *g = Some(t);
        }
    }

    pub fn unregister(&self) {
        if let Ok(mut g) = self.waiter.lock() {
            *g = None;
        }
    }
}

impl Default for WakeupCounter {
    fn default() -> Self {
        Self::new()
    }
}

pub trait TransportHandle {
    fn send(&self, recipient: usize, payload: &[u8]) -> io::Result<()>;
    fn recv_batch(&self, max_items: usize) -> io::Result<Vec<Vec<u8>>>;
    fn pending_inbound(&self) -> usize;
    fn pending_outbound(&self) -> usize;
    fn wakeup_seq(&self) -> u64;
}

pub fn snapshot(handle: &dyn TransportHandle) -> TransportSnapshot {
    TransportSnapshot {
        pending_inbound: handle.pending_inbound(),
        pending_outbound: handle.pending_outbound(),
        wakeup_seq: handle.wakeup_seq(),
    }
}
