mod acs;
mod cli;
mod codec;
mod node_runtime;
mod pool_reuse;

#[cfg(test)]
pub(crate) use acs::AcsRoundOutcome;
#[cfg(test)]
pub(crate) use acs::harness::serialize_crypto_payloads;
pub(crate) use acs::proposal::{AvailableProposal, ProposalStore};
pub(crate) use acs::protocol::AcsProtocol;
pub(crate) use acs::{AcsBackend, AcsBackendStats, AcsEvent, build_acs_backend};
pub(crate) use codec::hex_encode;
pub(crate) use honey_node::hb::{
    BatchDecryptor as HbBatchDecryptor, HbPkePrivateKeyShare, HbPkePublicParams,
    decode_tx_batch as decode_hb_tx_batch, encode_json_string as encode_hb_json_string,
    encode_tx_batch as encode_hb_tx_batch, merge_tx_batches_bytes as merge_hb_tx_batches_bytes,
    seal_encrypted_batch as seal_hb_encrypted_batch,
};
pub(crate) use node_runtime::args::NodeRuntimeArgs;
pub(crate) use node_runtime::digest::{GENESIS_CHAIN_DIGEST, compute_chain_digest, sha256_hex};
pub(crate) use node_runtime::io::current_time_millis;
pub(crate) use node_runtime::phase_stats::{DriverHostPhaseStats, DriverPhaseStats};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::parse_cli(std::env::args())?;
    node_runtime::run_rust_driver_node(args).map_err(Into::into)
}
