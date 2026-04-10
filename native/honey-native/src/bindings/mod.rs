use pyo3::prelude::*;

mod codec;
mod ecdsa;
mod host_crypto;
mod merkle;
mod threshold_sig;
mod tx_pool;

// Not registered (zero Python call sites):
// mod key_storage;       -- save/load_sig/pke_keys
// mod ledger;            -- SqliteLedgerStore now lives in honey-node
// mod local_transport;   -- LocalTcpTransport now lives in honey-node

pub fn register_all(m: &Bound<'_, PyModule>) -> PyResult<()> {
    merkle::register(m)?;
    threshold_sig::register(m)?;
    ecdsa::register(m)?;
    codec::register(m)?;
    tx_pool::register(m)?;
    host_crypto::register(m)?;
    Ok(())
}
