"""Broadcast Memory Pool (Mempool)

This module stores broadcast outputs across rounds. It serves two roles:
- the original RBC storage used by HoneyBadger's BKR93 path
- reusable PRBC carry-over entries used by Dumbo pool reuse
"""

import hashlib
import logging
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BroadcastData:
    """Complete broadcast data for a single reliable broadcast instance."""

    payload: bytes
    roothash: bytes
    shards: list[bytes | None]
    proofs: list[bytes | None]
    round_no: int
    sender_id: int
    timestamp: float
    protocol: str = "rbc"
    proof_payload: bytes | None = None
    selected_in_round: int | None = None
    consumed_in_round: int | None = None
    reuse_count: int = 0


class BroadcastMempool:
    """In-memory pool for broadcast data and reusable carry-over entries."""

    def __init__(self, max_size: int = 10000, expire_rounds: int = 5):
        self.max_size = max_size
        self.expire_rounds = expire_rounds
        self._storage: OrderedDict[str, BroadcastData] = OrderedDict()
        self._index_by_round_sender: dict[tuple[int, int], str] = {}
        self._payload_ids_by_hash: dict[bytes, str] = {}

    def add(
        self,
        payload: bytes,
        roothash: bytes,
        shards: Sequence[bytes | None],
        proofs: Sequence[bytes | None],
        round_no: int,
        sender_id: int,
        timestamp: float,
    ) -> str:
        payload_id = self._compute_payload_id(round_no, sender_id, roothash)
        if payload_id in self._storage:
            logger.debug(f"Payload {payload_id[:8]}... already in mempool")
            return payload_id

        self._ensure_capacity()
        broadcast_data = BroadcastData(
            payload=payload,
            roothash=roothash,
            shards=list(shards),
            proofs=list(proofs),
            round_no=round_no,
            sender_id=sender_id,
            timestamp=timestamp,
            protocol="rbc",
        )
        self._store(payload_id, broadcast_data)
        return payload_id

    def add_reusable(
        self,
        *,
        payload: bytes,
        roothash: bytes,
        proof_payload: bytes,
        round_no: int,
        sender_id: int,
        timestamp: float,
    ) -> str:
        payload_id = self._compute_payload_id(round_no, sender_id, roothash)
        existing = self._storage.get(payload_id)
        if existing is not None:
            return payload_id

        self._ensure_capacity()
        broadcast_data = BroadcastData(
            payload=payload,
            roothash=roothash,
            shards=[],
            proofs=[],
            round_no=round_no,
            sender_id=sender_id,
            timestamp=timestamp,
            protocol="prbc",
            proof_payload=proof_payload,
        )
        self._store(payload_id, broadcast_data)
        logger.debug(
            "Added reusable carry-over %s... (round=%s sender=%s size=%s)",
            payload_id[:8],
            round_no,
            sender_id,
            len(self._storage),
        )
        return payload_id

    def get(self, payload_id: str) -> BroadcastData | None:
        data = self._storage.get(payload_id)
        if data is None:
            logger.warning(f"Payload {payload_id[:8]}... not found in mempool")
            return None

        self._storage.move_to_end(payload_id)
        return data

    def get_reusable(self, payload_id: str) -> BroadcastData | None:
        data = self.get(payload_id)
        if data is None or data.protocol != "prbc":
            return None
        return data

    def get_by_hash(self, roothash: bytes) -> BroadcastData | None:
        payload_id = self._payload_ids_by_hash.get(roothash)
        if payload_id is None:
            return None
        return self.get(payload_id)

    def get_by_round_sender(self, round_no: int, sender_id: int) -> BroadcastData | None:
        payload_id = self._index_by_round_sender.get((round_no, sender_id))
        if payload_id is None:
            return None
        return self.get(payload_id)

    def list_round(self, round_no: int) -> dict[int, str]:
        return {
            sender_id: payload_id
            for (r, sender_id), payload_id in self._index_by_round_sender.items()
            if r == round_no
        }

    def list_unused(self, round_no: int, selected_senders: set[int]) -> list[tuple[int, str]]:
        return [
            (sender_id, payload_id)
            for (r, sender_id), payload_id in self._index_by_round_sender.items()
            if r == round_no and sender_id not in selected_senders
        ]

    def list_reusable(
        self,
        *,
        current_round: int,
        sender_id: int | None = None,
        limit: int = 1,
    ) -> list[tuple[str, BroadcastData]]:
        reusable = [
            (payload_id, data)
            for payload_id, data in self._storage.items()
            if data.protocol == "prbc"
            and data.consumed_in_round is None
            and data.round_no < current_round
            and (sender_id is None or data.sender_id == sender_id)
        ]
        reusable.sort(key=lambda item: (item[1].round_no, item[1].sender_id, item[0]))
        return reusable[:limit]

    def mark_selected(self, payload_id: str, round_id: int) -> None:
        if (data := self._storage.get(payload_id)) is not None:
            data.selected_in_round = round_id

    def mark_consumed(self, payload_id: str, round_id: int) -> None:
        if (data := self._storage.get(payload_id)) is not None:
            data.consumed_in_round = round_id
            data.reuse_count += 1

    def cleanup(self, current_round: int) -> None:
        expire_before_round = current_round - self.expire_rounds
        to_delete = [
            payload_id
            for payload_id, data in self._storage.items()
            if data.round_no < expire_before_round
        ]
        for payload_id in to_delete:
            self._delete_entry(payload_id)
        if to_delete:
            logger.debug(f"Cleaned up {len(to_delete)} expired payloads from mempool")

    def stats(self) -> dict[str, Any]:
        if not self._storage:
            return {"size": 0, "rounds_covered": set()}

        rounds = set(data.round_no for data in self._storage.values())
        reusable = sum(1 for data in self._storage.values() if data.protocol == "prbc")
        consumed = sum(1 for data in self._storage.values() if data.consumed_in_round is not None)
        return {
            "size": len(self._storage),
            "max_size": self.max_size,
            "rounds_covered": sorted(rounds),
            "oldest_round": min(data.round_no for data in self._storage.values()),
            "newest_round": max(data.round_no for data in self._storage.values()),
            "reusable": reusable,
            "consumed": consumed,
        }

    @staticmethod
    def _compute_payload_id(round_no: int, sender_id: int, roothash: bytes) -> str:
        combined = f"{round_no}:{sender_id}:{roothash.hex()}".encode()
        return hashlib.sha256(combined).hexdigest()[:16]

    def _ensure_capacity(self) -> None:
        if len(self._storage) >= self.max_size:
            self._evict_oldest()

    def _store(self, payload_id: str, data: BroadcastData) -> None:
        self._storage[payload_id] = data
        self._index_by_round_sender[(data.round_no, data.sender_id)] = payload_id
        self._payload_ids_by_hash[data.roothash] = payload_id

    def _evict_oldest(self) -> None:
        try:
            oldest_id, data = self._storage.popitem(last=False)
        except KeyError:
            return
        self._remove_indexes(oldest_id, data)
        logger.debug(f"Evicted oldest payload {oldest_id[:8]}... (LRU)")

    def _delete_entry(self, payload_id: str) -> None:
        data = self._storage.pop(payload_id, None)
        if data is None:
            return

        self._remove_indexes(payload_id, data)

    def _remove_indexes(self, payload_id: str, data: BroadcastData) -> None:
        self._index_by_round_sender.pop((data.round_no, data.sender_id), None)
        existing_id = self._payload_ids_by_hash.get(data.roothash)
        if existing_id == payload_id:
            self._payload_ids_by_hash.pop(data.roothash, None)
