from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass

from honey.crypto import sig
from honey.support.messages import CoinShareMessage
from honey.support.params import CommonParams
from honey.support.telemetry import METRICS


def sha256_hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


@dataclass
class CoinParams(CommonParams):
    PK: sig.PublicKey
    SK: sig.PrivateShare

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.PK.threshold != self.f + 1:
            raise ValueError(f"PK.threshold={self.PK.threshold} must equal f+1={self.f + 1}")
        if self.PK.players != self.N:
            raise ValueError(f"PK.players={self.PK.players} must equal N={self.N}")


class SharedCoin:
    def __init__(self, params: CoinParams, single_bit: bool = True) -> None:
        self.sid = params.sid
        self.pid = params.pid
        self.N = params.N
        self.f = params.f
        self.PK = params.PK
        self.SK = params.SK
        self.single_bit = single_bit

        self._received: dict[int, dict[int, bytes]] = {}
        self._output: dict[int, asyncio.Future] = {}
        self._purged_rounds: set[int] = set()

        self.logger = logging.getLogger(f"honey.coin.node{self.pid}")
        self._bg_task: asyncio.Task | None = None

    def start(self, task_group: asyncio.TaskGroup, receive_queue: asyncio.Queue) -> None:
        self._bg_task = task_group.create_task(self._recv_loop(receive_queue))

    def stop(self) -> None:
        if self._bg_task and not self._bg_task.done():
            self._bg_task.cancel()

    def _get_future(self, round_id: int) -> asyncio.Future:
        if round_id not in self._output:
            self._output[round_id] = asyncio.get_running_loop().create_future()
        return self._output[round_id]

    async def _recv_loop(self, receive_queue: asyncio.Queue) -> None:
        try:
            while True:
                sender_id, payload = await receive_queue.get()
                if not isinstance(payload, CoinShareMessage):
                    continue
                round_id = payload.round_id
                raw_sig = payload.signature

                if round_id in self._purged_rounds:
                    continue

                if not (0 <= sender_id < self.N):
                    self.logger.warning(f"Invalid sender ID: {sender_id}")
                    continue

                msg = f"{self.sid}:{round_id}".encode()

                if sender_id != self.pid:
                    try:
                        if not self.PK.verify_share(sender_id, raw_sig, msg):
                            self.logger.warning(
                                f"Invalid sig from {sender_id} for round {round_id}"
                            )
                            continue
                    except Exception as exc:
                        self.logger.error(f"Crypto error from {sender_id}: {exc}")
                        continue

                self._received.setdefault(round_id, {})[sender_id] = raw_sig
                self._try_output(round_id)

        except asyncio.CancelledError:
            pass

    def _try_output(self, round_id: int) -> None:
        fut = self._get_future(round_id)
        if fut.done() or len(self._received.get(round_id, {})) < self.f + 1:
            return

        msg = f"{self.sid}:{round_id}".encode()
        try:
            sig_combined = sig.combine_shares(
                self.PK,
                dict(list(self._received[round_id].items())[: self.f + 1]),
                msg,
            )
            coin = sha256_hash(sig_combined)[0]
            fut.set_result(coin % 2 if self.single_bit else coin)
            METRICS.increment("coin.output", node=self.pid, round=round_id)
        except Exception as exc:
            self.logger.error(f"Failed to combine shares for round {round_id}: {exc}")

    async def get_coin(self, round_id: int, broadcast_queue: asyncio.Queue) -> int:
        if round_id in self._purged_rounds:
            raise ValueError(f"Round {round_id} has already been purged.")

        msg = f"{self.sid}:{round_id}".encode()
        sig_share = self.SK.sign(msg)
        await broadcast_queue.put(CoinShareMessage(round_id=round_id, signature=sig_share))

        self._received.setdefault(round_id, {})[self.pid] = sig_share
        self._try_output(round_id)
        return await self._get_future(round_id)

    def purge_round(self, round_id: int) -> None:
        self._purged_rounds.add(round_id)
        self._received.pop(round_id, None)
        self._output.pop(round_id, None)
