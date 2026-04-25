use honey_node::transport::NetworkFaultConfig;
use serde_json::Value;

pub(super) struct BroadcastPoolConfig {
    pub(super) max_size: usize,
    pub(super) expire_rounds: u32,
    pub(super) enable_reuse: bool,
    pub(super) enable_reference_proposals: bool,
    pub(super) enable_fetch_fallback: bool,
    pub(super) reuse_limit_per_round: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ByzantineBehavior {
    Silent,
    InvalidFetchResponse,
}

impl ByzantineBehavior {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Silent => "silent",
            Self::InvalidFetchResponse => "invalid_fetch_response",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "silent" => Ok(Self::Silent),
            "invalid_fetch_response" => Ok(Self::InvalidFetchResponse),
            other => Err(format!("unsupported byzantine behavior: {other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ByzantineNodeConfig {
    pub(super) behavior: Option<ByzantineBehavior>,
}

impl ByzantineNodeConfig {
    pub(super) fn behavior_label(self) -> &'static str {
        self.behavior
            .map(ByzantineBehavior::as_str)
            .unwrap_or("none")
    }

    pub(super) fn is_silent(self) -> bool {
        self.behavior == Some(ByzantineBehavior::Silent)
    }

    pub(super) fn sends_invalid_fetch_response(self) -> bool {
        self.behavior == Some(ByzantineBehavior::InvalidFetchResponse)
    }
}

pub(super) fn parse_broadcast_pool_config(
    config_json: &str,
) -> Result<BroadcastPoolConfig, String> {
    let value: Value = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
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
    Ok(BroadcastPoolConfig {
        max_size,
        expire_rounds,
        enable_reuse,
        enable_reference_proposals,
        enable_fetch_fallback,
        reuse_limit_per_round,
    })
}

pub(super) fn parse_network_fault_config(
    config_json: &str,
    pid: usize,
) -> Result<NetworkFaultConfig, String> {
    let value: Value = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
    let Some(network_value) = value.get("network_faults") else {
        return Ok(NetworkFaultConfig::default());
    };
    let network = network_value
        .as_object()
        .ok_or_else(|| String::from("network_faults must be a JSON object"))?;

    let enabled = network
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !enabled {
        return Ok(NetworkFaultConfig::default());
    }

    let seed = network.get("seed").and_then(Value::as_u64).unwrap_or(0);
    let fixed_delay_ms = network
        .get("fixed_delay_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let jitter_ms = network
        .get("jitter_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let slow_honest_extra_delay_ms = parse_slow_honest_extra_delay_ms(network_value, pid)?;

    Ok(NetworkFaultConfig {
        enabled,
        seed,
        fixed_delay_ms,
        jitter_ms,
        slow_honest_extra_delay_ms,
    })
}

pub(super) fn parse_byzantine_node_config(
    config_json: &str,
    pid: usize,
) -> Result<ByzantineNodeConfig, String> {
    let value: Value = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
    let Some(nodes_value) = value.get("byzantine_nodes") else {
        return Ok(ByzantineNodeConfig::default());
    };
    let nodes = nodes_value
        .as_array()
        .ok_or_else(|| String::from("byzantine_nodes must be a JSON array"))?;
    let mut matched_behavior = None;
    for entry_value in nodes {
        let entry = entry_value
            .as_object()
            .ok_or_else(|| String::from("byzantine_nodes entries must be JSON objects"))?;
        let entry_pid = entry
            .get("pid")
            .and_then(Value::as_u64)
            .ok_or_else(|| String::from("byzantine_nodes[].pid must be an integer"))?
            as usize;
        let behavior = ByzantineBehavior::parse(
            entry
                .get("behavior")
                .and_then(Value::as_str)
                .ok_or_else(|| String::from("byzantine_nodes[].behavior must be a string"))?,
        )?;
        if entry_pid != pid {
            continue;
        }
        if matched_behavior.replace(behavior).is_some() {
            return Err(format!(
                "duplicate byzantine_nodes entry configured for pid {pid}"
            ));
        }
    }
    Ok(ByzantineNodeConfig {
        behavior: matched_behavior,
    })
}

fn parse_slow_honest_extra_delay_ms(network_faults: &Value, pid: usize) -> Result<u64, String> {
    let Some(slow_honest_value) = network_faults.get("slow_honest") else {
        return Ok(0);
    };
    let slow_honest = slow_honest_value
        .as_object()
        .ok_or_else(|| String::from("network_faults.slow_honest must be a JSON object"))?;
    let extra_delay_ms = slow_honest
        .get("extra_delay_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let Some(pids_value) = slow_honest.get("pids") else {
        return Ok(0);
    };
    let pids = pids_value
        .as_array()
        .ok_or_else(|| String::from("network_faults.slow_honest.pids must be an array"))?;
    let pid_matches = pids.iter().any(|value| value.as_u64() == Some(pid as u64));
    Ok(if pid_matches { extra_delay_ms } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::{ByzantineBehavior, parse_byzantine_node_config, parse_network_fault_config};

    #[test]
    fn parse_network_fault_config_defaults_to_disabled() {
        let config = parse_network_fault_config("{}", 0).expect("config should parse");

        assert!(!config.enabled);
        assert_eq!(config.fixed_delay_ms, 0);
        assert_eq!(config.jitter_ms, 0);
        assert_eq!(config.slow_honest_extra_delay_ms, 0);
    }

    #[test]
    fn parse_network_fault_config_applies_slow_honest_only_to_selected_pid() {
        let config = parse_network_fault_config(
            r#"{
                "network_faults": {
                    "enabled": true,
                    "seed": 42,
                    "fixed_delay_ms": 10,
                    "jitter_ms": 15,
                    "slow_honest": {
                        "pids": [1, 3],
                        "extra_delay_ms": 70
                    }
                }
            }"#,
            3,
        )
        .expect("config should parse");

        assert!(config.enabled);
        assert_eq!(config.seed, 42);
        assert_eq!(config.fixed_delay_ms, 10);
        assert_eq!(config.jitter_ms, 15);
        assert_eq!(config.slow_honest_extra_delay_ms, 70);
    }

    #[test]
    fn parse_byzantine_node_config_defaults_to_none() {
        let config = parse_byzantine_node_config("{}", 0).expect("config should parse");

        assert_eq!(config.behavior, None);
        assert_eq!(config.behavior_label(), "none");
    }

    #[test]
    fn parse_byzantine_node_config_selects_matching_pid() {
        let config = parse_byzantine_node_config(
            r#"{
                "byzantine_nodes": [
                    {"pid": 1, "behavior": "silent"},
                    {"pid": 3, "behavior": "invalid_fetch_response"}
                ]
            }"#,
            3,
        )
        .expect("config should parse");

        assert_eq!(
            config.behavior,
            Some(ByzantineBehavior::InvalidFetchResponse)
        );
        assert_eq!(config.behavior_label(), "invalid_fetch_response");
    }

    #[test]
    fn parse_byzantine_node_config_rejects_duplicate_pid_entries() {
        let error = parse_byzantine_node_config(
            r#"{
                "byzantine_nodes": [
                    {"pid": 2, "behavior": "silent"},
                    {"pid": 2, "behavior": "invalid_fetch_response"}
                ]
            }"#,
            2,
        )
        .expect_err("duplicate pid entries should fail");

        assert!(error.contains("duplicate byzantine_nodes entry"));
    }
}
