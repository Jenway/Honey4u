use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const GENESIS_CHAIN_DIGEST: [u8; 32] = [0; 32];

fn hex_encode(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn sha256_hex(payload: &[u8]) -> String {
    hex_encode(&Sha256::digest(payload))
}

fn compute_chain_digest(prev_digest: &[u8], round_id: u64, block_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_digest);
    hasher.update(round_id.to_be_bytes());
    hasher.update(block_payload);
    hasher.finalize().into()
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create ledger directory: {e}"))?;
    }
    Ok(())
}

fn ensure_meta(conn: &Connection, key: &str, value: &str) -> Result<(), String> {
    let existing = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| format!("failed to read ledger metadata: {e}"))?;

    if let Some(existing_value) = existing {
        if existing_value != value {
            return Err(format!(
                "ledger metadata mismatch for {key}: expected {value}, found {existing_value}"
            ));
        }
        return Ok(());
    }

    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)",
        params![key, value],
    )
    .map_err(|e| format!("failed to write ledger metadata: {e}"))?;
    Ok(())
}

pub struct SqliteLedgerStore {
    path: String,
    conn: Connection,
    chain_digest: Option<String>,
}

impl SqliteLedgerStore {
    pub fn new(path: &str, sid: &str, protocol: &str, pid: usize) -> Result<Self, String> {
        let path_buf = PathBuf::from(path);
        ensure_parent_dir(&path_buf)?;

        let conn = Connection::open(&path_buf)
            .map_err(|e| format!("failed to open sqlite ledger: {e}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS blocks (
                 round_id INTEGER PRIMARY KEY,
                 tx_count INTEGER NOT NULL,
                 delivered_at_ns INTEGER NOT NULL,
                 prev_chain_digest TEXT,
                 block_digest TEXT NOT NULL,
                 chain_digest TEXT NOT NULL,
                 block_payload BLOB NOT NULL
             );",
        )
        .map_err(|e| format!("failed to initialize sqlite ledger: {e}"))?;

        ensure_meta(&conn, "sid", sid)?;
        ensure_meta(&conn, "protocol", protocol)?;
        ensure_meta(&conn, "pid", &pid.to_string())?;

        let chain_digest = conn
            .query_row(
                "SELECT chain_digest FROM blocks ORDER BY round_id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| format!("failed to read ledger tip: {e}"))?;

        Ok(Self {
            path: path.to_owned(),
            conn,
            chain_digest,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn chain_digest(&self) -> Option<&str> {
        self.chain_digest.as_deref()
    }

    pub fn append_block(
        &mut self,
        round_id: usize,
        tx_count: usize,
        delivered_at_ns: u64,
        block_payload: &[u8],
    ) -> Result<(Option<String>, String, String), String> {
        let prev_chain_digest = self.chain_digest.clone();
        let prev_digest_bytes = prev_chain_digest
            .as_deref()
            .map(<[u8; 32]>::from_hex)
            .transpose()?
            .unwrap_or(GENESIS_CHAIN_DIGEST);
        let block_digest = sha256_hex(block_payload);
        let chain_digest_bytes =
            compute_chain_digest(&prev_digest_bytes, round_id as u64, block_payload);
        let chain_digest = hex_encode(&chain_digest_bytes);

        self.conn
            .execute(
                "INSERT INTO blocks (
                    round_id,
                    tx_count,
                    delivered_at_ns,
                    prev_chain_digest,
                    block_digest,
                    chain_digest,
                    block_payload
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    round_id as i64,
                    tx_count as i64,
                    delivered_at_ns as i64,
                    prev_chain_digest.clone(),
                    block_digest.clone(),
                    chain_digest.clone(),
                    block_payload,
                ],
            )
            .map_err(|e| format!("failed to append ledger block: {e}"))?;

        self.chain_digest = Some(chain_digest.clone());
        Ok((prev_chain_digest, block_digest, chain_digest))
    }

    pub fn close(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| format!("failed to checkpoint sqlite ledger: {e}"))?;
        Ok(())
    }
}

trait FromHex: Sized {
    fn from_hex(value: &str) -> Result<Self, String>;
}

impl FromHex for [u8; 32] {
    fn from_hex(value: &str) -> Result<Self, String> {
        if value.len() != 64 {
            return Err(String::from("invalid chain digest length"));
        }
        let mut bytes = [0u8; 32];
        for (idx, chunk) in value.as_bytes().chunks(2).enumerate() {
            let high = (chunk[0] as char)
                .to_digit(16)
                .ok_or_else(|| String::from("invalid chain digest state"))?;
            let low = (chunk[1] as char)
                .to_digit(16)
                .ok_or_else(|| String::from("invalid chain digest state"))?;
            bytes[idx] = ((high << 4) | low) as u8;
        }
        Ok(bytes)
    }
}
