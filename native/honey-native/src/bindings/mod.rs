use pyo3::prelude::*;

mod codec;
mod ecdsa;
mod host_crypto;
mod merkle;
mod threshold_pke;
mod threshold_sig;
mod tx_pool;

// Not registered (zero Python call sites; Rust internals use these directly):
// mod key_storage;       -- save/load_sig/pke_keys
// mod ledger;            -- SqliteLedgerStore
// mod local_transport;   -- LocalTcpTransport (honey-node uses transport::LocalTcpTransport directly)

pub fn register_all(m: &Bound<'_, PyModule>) -> PyResult<()> {
    merkle::register(m)?;
    threshold_sig::register(m)?;
    threshold_pke::register(m)?;
    ecdsa::register(m)?;
    codec::register(m)?;
    tx_pool::register(m)?;
    host_crypto::register(m)?;
    Ok(())
}
