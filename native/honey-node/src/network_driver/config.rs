use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BroadcastPoolBackend {
    None,
    Rust,
}

impl BroadcastPoolBackend {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Rust => "rust",
        }
    }
}

pub(super) struct BroadcastPoolConfig {
    pub(super) backend: BroadcastPoolBackend,
    pub(super) max_size: usize,
    pub(super) expire_rounds: u32,
    pub(super) enable_reuse: bool,
    pub(super) enable_reference_proposals: bool,
    pub(super) enable_fetch_fallback: bool,
    pub(super) reuse_limit_per_round: usize,
}

pub(super) fn parse_broadcast_pool_config(
    config_json: &str,
) -> Result<BroadcastPoolConfig, String> {
    let value: Value = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
    let backend = match value
        .get("broadcast_mempool_backend")
        .and_then(Value::as_str)
        .unwrap_or("rust")
    {
        "none" => BroadcastPoolBackend::None,
        "rust" => BroadcastPoolBackend::Rust,
        other => {
            return Err(format!(
                "unsupported broadcast_mempool_backend in config_json: {other}"
            ));
        }
    };
    let max_size = value
        .get("pool_mempool_max")
        .and_then(Value::as_u64)
        .unwrap_or(1000) as usize;
    let expire_rounds = value
        .get("pool_expire_rounds")
        .and_then(Value::as_u64)
        .unwrap_or(5) as u32;
    let enable_reuse = value
        .get("enable_broadcast_pool_reuse")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let enable_reference_proposals = value
        .get("enable_pool_reference_proposals")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let enable_fetch_fallback = value
        .get("enable_pool_fetch_fallback")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reuse_limit_per_round = value
        .get("pool_reuse_limit_per_round")
        .and_then(Value::as_u64)
        .unwrap_or(1) as usize;
    if enable_reuse && backend == BroadcastPoolBackend::None {
        return Err(String::from(
            "broadcast_mempool_backend=none is incompatible with enable_broadcast_pool_reuse=true",
        ));
    }
    Ok(BroadcastPoolConfig {
        backend,
        max_size,
        expire_rounds,
        enable_reuse,
        enable_reference_proposals,
        enable_fetch_fallback,
        reuse_limit_per_round,
    })
}
