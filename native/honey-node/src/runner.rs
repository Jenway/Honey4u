use std::path::PathBuf;

/// A spawned child process running a single node instance.
/// Used by drive_hb, drive_dumbo, and network_driver to manage multiprocess runs.
pub(crate) struct SpawnedNode {
    pub(crate) pid: usize,
    pub(crate) child: std::process::Child,
    pub(crate) result_path: PathBuf,
    pub(crate) stderr_path: PathBuf,
}
