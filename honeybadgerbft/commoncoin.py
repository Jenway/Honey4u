import asyncio
import hashlib
import logging
from dataclasses import dataclass

from crypto import threshsig
from honeybadgerbft.params import CommonParams


def sha256_hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


@dataclass
class CoinParams(CommonParams):
    PK: threshsig.SigPublicMaterial
    SK: threshsig.SigPrivateMaterial

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.PK.threshold != self.f + 1:
            raise ValueError(f"PK.threshold={self.PK.threshold} must equal f+1={self.f + 1}")
        if self.PK.players != self.N:
            raise ValueError(f"PK.players={self.PK.players} must equal N={self.N}")


class SharedCoin:
    """
    Shared coin protocol based on threshold signatures.
    """

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

        self.logger = logging.getLogger(f"honeybadgerbft.coin.node{self.pid}")
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
                tag, round_id, raw_sig = payload

                if tag != "COIN":
                    continue

                if round_id in self._purged_rounds:
                    continue  # 直接忽略已完成轮次的迟到消息

                if not (0 <= sender_id < self.N):
                    self.logger.warning(f"Invalid sender ID: {sender_id}")
                    continue

                msg = f"{self.sid}:{round_id}".encode()

                if sender_id != self.pid:
                    try:
                        if not threshsig.verify_share(self.PK, raw_sig, sender_id, msg):
                            self.logger.warning(
                                f"Invalid sig from {sender_id} for round {round_id}"
                            )
                            continue
                    except Exception as e:
                        self.logger.error(f"Crypto error from {sender_id}: {e}")
                        continue

                if round_id not in self._received:
                    self._received[round_id] = {}
                self._received[round_id][sender_id] = raw_sig
                self._try_output(round_id)

        except asyncio.CancelledError:
            # 捕获 TaskGroup 发出的 cancel 信号，静默退出循环
            pass

    def _try_output(self, round_id: int) -> None:
        """检查是否集齐 f+1 个签名并尝试输出硬币"""
        fut = self._get_future(round_id)
        # 如果 Future 已经被赋值（已完成本轮），或者分片不足，则跳过
        if fut.done() or len(self._received.get(round_id, {})) < self.f + 1:
            return

        sigs = dict(list(self._received[round_id].items())[: self.f + 1])
        msg = f"{self.sid}:{round_id}".encode()

        try:
            sig_combined = threshsig.combine_shares(self.PK, sigs, msg)
            coin = sha256_hash(sig_combined)[0]
            coin_value = coin % 2 if self.single_bit else coin
            fut.set_result(coin_value)  # 唤醒 get_coin 等待者
        except Exception as e:
            self.logger.error(f"Failed to combine shares for round {round_id}: {e}")

    async def get_coin(self, round_id: int, broadcast_queue: asyncio.Queue) -> int:
        """对外接口：生成本节点分片并广播，等待凑齐返回共同硬币"""
        if round_id in self._purged_rounds:
            raise ValueError(f"Round {round_id} has already been purged.")

        msg = f"{self.sid}:{round_id}".encode()
        sig = threshsig.sign(self.SK, msg)

        await broadcast_queue.put(("COIN", round_id, sig))

        if round_id not in self._received:
            self._received[round_id] = {}
        self._received[round_id][self.pid] = sig
        self._try_output(round_id)

        return await self._get_future(round_id)

    def purge_round(self, round_id: int) -> None:
        self._purged_rounds.add(round_id)
        self._received.pop(round_id, None)
        self._output.pop(round_id, None)
