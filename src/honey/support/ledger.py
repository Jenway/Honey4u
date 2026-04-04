from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol, cast

import honey_native

_GENESIS_CHAIN_DIGEST = bytes(32)
_SQLITE_LEDGER_STORE = cast(type[object], honey_native.__dict__["SqliteLedgerStore"])


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    sid: str
    pid: int
    protocol: str
    round_id: int
    tx_count: int
    delivered_at_ns: int
    prev_chain_digest: str | None
    block_digest: str
    chain_digest: str
    block_payload_hex: str
    tx_previews: tuple[str, ...] = ()


class LedgerSink(Protocol):
    @property
    def ledger_path(self) -> str | None: ...

    @property
    def chain_digest(self) -> str | None: ...

    def append_block(
        self,
        *,
        round_id: int,
        tx_count: int,
        delivered_at_ns: int,
        block_payload: bytes,
    ) -> tuple[str | None, str, str]: ...

    def close(self) -> None: ...


class NoopLedgerSink:
    @property
    def ledger_path(self) -> str | None:
        return None

    @property
    def chain_digest(self) -> str | None:
        return None

    def append_block(
        self,
        *,
        round_id: int,
        tx_count: int,
        delivered_at_ns: int,
        block_payload: bytes,
    ) -> tuple[str | None, str, str]:
        del round_id, tx_count, delivered_at_ns, block_payload
        raise RuntimeError("NoopLedgerSink does not persist blocks")

    def close(self) -> None:
        return None


class SqliteLedgerSink:
    def __init__(self, path: Path, *, sid: str, protocol: str, pid: int) -> None:
        self._store = _SQLITE_LEDGER_STORE(str(path), sid, protocol, pid)

    @property
    def ledger_path(self) -> str:
        return str(self._store.path)

    @property
    def chain_digest(self) -> str | None:
        return self._store.chain_digest

    def append_block(
        self,
        *,
        round_id: int,
        tx_count: int,
        delivered_at_ns: int,
        block_payload: bytes,
    ) -> tuple[str | None, str, str]:
        return cast(
            tuple[str | None, str, str],
            self._store.append_block(round_id, tx_count, delivered_at_ns, block_payload),
        )

    def close(self) -> None:
        self._store.close()


def _compute_block_digest(block_payload: bytes) -> str:
    return sha256(block_payload).hexdigest()


def _compute_chain_digest(prev_digest: bytes, round_id: int, block_payload: bytes) -> bytes:
    return sha256(prev_digest + round_id.to_bytes(8, "big", signed=False) + block_payload).digest()


def _safe_component(value: str) -> str:
    sanitized = [char if char.isalnum() or char in {"-", "_"} else "_" for char in value]
    collapsed = "".join(sanitized).strip("_")
    return collapsed or "session"


def build_sqlite_ledger_sink(
    root_dir: str, *, sid: str, protocol: str, pid: int
) -> SqliteLedgerSink:
    base = Path(root_dir) / _safe_component(sid) / protocol
    return SqliteLedgerSink(base / f"node-{pid}.sqlite3", sid=sid, protocol=protocol, pid=pid)


class LedgerRecorder:
    def __init__(
        self,
        *,
        sid: str,
        pid: int,
        protocol: str,
        sink: LedgerSink | None = None,
    ) -> None:
        self._sid = sid
        self._pid = pid
        self._protocol = protocol
        self._sink = sink or NoopLedgerSink()
        self._chain_digest: str | None = self._sink.chain_digest
        self._block_digests: list[str] = []

    @property
    def chain_digest(self) -> str | None:
        return self._chain_digest

    @property
    def ledger_path(self) -> str | None:
        return self._sink.ledger_path

    @property
    def block_digests(self) -> tuple[str, ...]:
        return tuple(self._block_digests)

    def append_block(
        self,
        *,
        round_id: int,
        block_payload: bytes,
        tx_count: int,
        delivered_at_ns: int,
    ) -> LedgerRecord:
        prev_chain_digest = self.chain_digest
        if isinstance(self._sink, NoopLedgerSink):
            block_digest = _compute_block_digest(block_payload)
            prev_digest_bytes = (
                bytes.fromhex(prev_chain_digest) if prev_chain_digest else _GENESIS_CHAIN_DIGEST
            )
            chain_digest = _compute_chain_digest(prev_digest_bytes, round_id, block_payload).hex()
        else:
            prev_chain_digest, block_digest, chain_digest = self._sink.append_block(
                round_id=round_id,
                tx_count=tx_count,
                delivered_at_ns=delivered_at_ns,
                block_payload=block_payload,
            )
        record = LedgerRecord(
            sid=self._sid,
            pid=self._pid,
            protocol=self._protocol,
            round_id=round_id,
            tx_count=tx_count,
            delivered_at_ns=delivered_at_ns,
            prev_chain_digest=prev_chain_digest,
            block_digest=block_digest,
            chain_digest=chain_digest,
            block_payload_hex=block_payload.hex(),
        )
        self._chain_digest = chain_digest
        self._block_digests.append(block_digest)
        return record

    def close(self) -> None:
        self._sink.close()
