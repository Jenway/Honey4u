use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

#[derive(Debug)]
pub(crate) struct WakeupCounter {
    seq: AtomicU64,
    waiter: Mutex<Option<thread::Thread>>,
}

impl WakeupCounter {
    pub(crate) fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            waiter: Mutex::new(None),
        }
    }

    pub(crate) fn notify(&self) {
        self.seq.fetch_add(1, Ordering::Relaxed);
        let maybe_thread = self.waiter.lock().ok().and_then(|g| g.clone());
        if let Some(t) = maybe_thread {
            t.unpark();
        }
    }

    pub(crate) fn register(&self, t: thread::Thread) {
        if let Ok(mut g) = self.waiter.lock() {
            *g = Some(t);
        }
    }

    pub(crate) fn unregister(&self) {
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
