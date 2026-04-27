// driver_node/args.rs
use clap::Parser;
use honey_acs::protocol::AcsProtocol;

#[derive(Parser)]
pub(crate) struct NodeRuntimeArgs {
    #[arg(short, long, default_value_t = 0)]
    pub(crate) pid: usize,
    #[arg(long, default_value = "driver:hb")]
    pub(crate) sid: String,
    #[arg(long, value_parser = AcsProtocol::parse, default_value = "hb")]
    pub(crate) acs_protocol: AcsProtocol,
    #[arg(long, default_value_t = 4)]
    pub(crate) nodes: usize,
    #[arg(long, default_value_t = 1)]
    pub(crate) faulty: usize,
    #[arg(long, default_value_t = 1)]
    pub(crate) rounds: usize,
    #[arg(long, default_value_t = 1)]
    pub(crate) batch_size: usize,
    #[arg(long, default_value_t = 30.0)]
    pub(crate) global_timeout: f64,
    #[arg(long, required = true)]
    pub(crate) addresses_json: String,
    #[arg(long, required = true)]
    pub(crate) hb_crypto_json: String,
    #[arg(long, required = true)]
    pub(crate) acs_crypto_json: String,
    #[arg(long, default_value = "{}")]
    pub(crate) config_json: String,
    #[arg(long)]
    pub(crate) start_at_ms: Option<u64>,
    #[arg(long)]
    pub(crate) result_path: Option<String>,
}

impl NodeRuntimeArgs {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.nodes == 0 {
            return Err("--nodes must be > 0".into());
        }
        if self.pid >= self.nodes {
            return Err(format!(
                "--pid {} must be < --nodes {}",
                self.pid, self.nodes
            ));
        }
        if self.rounds == 0 {
            return Err("--rounds must be > 0".into());
        }
        if self.batch_size == 0 {
            return Err("--batch-size must be > 0".into());
        }
        if self.global_timeout <= 0.0 {
            return Err("--global-timeout must be > 0".into());
        }
        Ok(())
    }
}
