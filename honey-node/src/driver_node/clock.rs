use super::error::{DriverError, DriverResult};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn current_time_millis() -> DriverResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| DriverError::clock(err.to_string()))?;
    u64::try_from(duration.as_millis()).map_err(|_| DriverError::clock("current time overflow"))
}

pub(crate) fn wait_until_start(start_at_ms: Option<u64>) -> DriverResult<()> {
    let Some(start_at_ms) = start_at_ms else {
        return Ok(());
    };
    let now_ms = current_time_millis()?;
    if start_at_ms <= now_ms {
        return Ok(());
    }
    thread::sleep(Duration::from_millis(start_at_ms - now_ms));
    Ok(())
}
