import asyncio
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from honey.acs.bkr93 import CSParams, run_bkr93_acs
from honey.consensus.honeybadger.block import honeybadger_block
from honey.data.broadcast_mempool import BroadcastMempool
from honey.runtime.node_mailbox import NodeMailboxRouter
from honey.runtime.router import AbaRecv, CoinRecv, RbcRecv, RoundProtocolRouter, TpkeRecv
from honey.support.exceptions import ProtocolInvariantError, RoutingError, SerializationError
from honey.support.messages import (
    Channel,
    ProtocolMessage,
    decode_tx,
    decode_tx_batch,
    encode_tx,
    encode_tx_batch,
    tx_dedup_key,
)
from honey.support.params import CommonParams, CryptoParams, HBConfig
from honey.support.results import Failure, Result, Success, failure, success
from honey.support.telemetry import METRICS, log_event, timed_metric
from network.transport import Transport


@dataclass
class RoundContext:
    round_id: int
    sid: str
    pid: int
    n: int
    f: int
    router: RoundProtocolRouter
    coin_recvs: list[asyncio.Queue[CoinRecv]]
    aba_recvs: list[asyncio.Queue[AbaRecv]]
    rbc_recvs: list[asyncio.Queue[RbcRecv]]
    tpke_recv: asyncio.Queue[TpkeRecv]
    tpke_bcast_queue: asyncio.Queue[ProtocolMessage]
    my_rbc_input: asyncio.Queue[bytes]
    acs_output_queue: asyncio.Queue[tuple[bytes | None, ...]]
    tasks: list[asyncio.Task[Any]] = field(default_factory=list)


class HoneyBadgerBFT:
    def __init__(
        self,
        common_params: CommonParams,
        crypto_params: CryptoParams,
        transport: Transport,
        config: HBConfig | None = None,
    ):
        self.common = common_params
        self.crypto = crypto_params
        self.transport = transport
        self.config = config or HBConfig()
        self.logger = logging.LoggerAdapter(
            logging.getLogger("honey.hb"),
            extra={"node": common_params.pid},
        )
        self.mailboxes = NodeMailboxRouter(self.transport, self.logger)
        self.round = 0
        self.transaction_buffer = deque()
        self.mempool = BroadcastMempool(max_size=1000, expire_rounds=self.config.pool_expire_rounds)
        self.K = self.config.max_rounds
        self.txcnt = 0
        self.round_latencies: list[float] = []
        self.round_proposed_counts: list[int] = []
        self.round_delivered_counts: list[int] = []
        self.origin_tx_latencies: list[float] = []
        self.origin_tx_latencies_by_round: list[tuple[float, ...]] = []
        self._tracked_submission_times_ns: dict[str, int] = {}

    def submit_tx(
        self,
        tx: Any,
        *,
        track_latency: bool = False,
        submitted_at_ns: int | None = None,
    ) -> None:
        self.transaction_buffer.append(tx)
        if track_latency:
            self._tracked_submission_times_ns[self._tx_dedup_key(tx)] = (
                submitted_at_ns if submitted_at_ns is not None else time.time_ns()
            )

    async def run(self) -> None:
        mailbox_task = asyncio.create_task(self.mailboxes.run())
        log_event(self.logger, logging.INFO, "hb_start", sid=self.common.sid, max_rounds=self.K)
        await asyncio.sleep(0)
        if mailbox_task.done():
            await mailbox_task

        try:
            while True:
                if mailbox_task.done():
                    await mailbox_task

                round_id = self.round
                self.mailboxes.inbox(round_id)

                tx_to_send = []
                for _ in range(self.config.batch_size):
                    if self.transaction_buffer:
                        tx_to_send.append(self.transaction_buffer.popleft())
                if not tx_to_send:
                    await asyncio.sleep(0.1)
                    continue

                METRICS.increment("hb.round.started", node=self.common.pid)
                log_event(
                    self.logger,
                    logging.DEBUG,
                    "round_start",
                    round=round_id,
                    batch_size=len(tx_to_send),
                )
                round_start = time.perf_counter()
                with timed_metric("hb.round.seconds", node=self.common.pid, round=round_id):
                    round_result = await self._run_round(round_id, tx_to_send)
                self.round_latencies.append(time.perf_counter() - round_start)

                self._apply_round_result(round_id, tx_to_send, round_result)
                self._finish_round(round_id)
                self.round += 1
                if self.round >= self.K:
                    break
        finally:
            mailbox_task.cancel()
            try:
                await mailbox_task
            except asyncio.CancelledError:
                pass

        log_event(
            self.logger,
            logging.INFO,
            "hb_finish",
            sid=self.common.sid,
            rounds=self.K,
            delivered=self.txcnt,
        )

    def _apply_round_result(
        self, round_id: int, tx_to_send: list[Any], round_result: Result[list[Any]]
    ) -> None:
        self.round_proposed_counts.append(len(tx_to_send))

        if isinstance(round_result, Success):
            new_tx = round_result.value
            tx_cnt = len(new_tx)
            self.txcnt += tx_cnt
            origin_latencies = tuple(self._record_origin_tx_latencies(new_tx))
            self.round_delivered_counts.append(tx_cnt)
            self.origin_tx_latencies_by_round.append(origin_latencies)
            METRICS.increment("hb.round.succeeded", node=self.common.pid)
            METRICS.increment("hb.tx.delivered", tx_cnt, node=self.common.pid)
            self.logger.info(
                f"Delivered ACS Block in Round {round_id} with {tx_cnt} TXs",
                extra={"round": round_id, "tx_count": tx_cnt},
            )

            for tx in tx_to_send:
                if tx not in new_tx:
                    self.transaction_buffer.appendleft(tx)
            return

        self.round_delivered_counts.append(0)
        self.origin_tx_latencies_by_round.append(())
        METRICS.increment("hb.round.failed", node=self.common.pid)
        if isinstance(round_result, Failure):
            self.logger.warning(
                "Round failed",
                extra={
                    "round": round_id,
                    "error_code": round_result.error_code,
                    "details": round_result.details,
                },
            )
        else:
            self.logger.warning("Round failed", extra={"round": round_id})
        for tx in reversed(tx_to_send):
            self.transaction_buffer.appendleft(tx)

    def _finish_round(self, round_id: int) -> None:
        self.mailboxes.close_round(round_id)

    def _record_origin_tx_latencies(self, delivered_txs: list[Any]) -> list[float]:
        delivered_at_ns = time.time_ns()
        round_latencies: list[float] = []
        for tx in delivered_txs:
            tx_key = self._tx_dedup_key(tx)
            submitted_at_ns = self._tracked_submission_times_ns.pop(tx_key, None)
            if submitted_at_ns is None:
                continue
            latency = max(0.0, (delivered_at_ns - submitted_at_ns) / 1_000_000_000)
            self.origin_tx_latencies.append(latency)
            round_latencies.append(latency)
        return round_latencies

    @staticmethod
    def _tx_dedup_key(tx: Any) -> str:
        return tx_dedup_key(tx)

    @classmethod
    def _merge_block_batches(cls, block: tuple[bytes, ...]) -> list[Any]:
        ordered_results: list[Any] = []
        seen: set[str] = set()

        for batch in block:
            decoded_batch = decode_tx_batch(batch)

            for raw_tx in decoded_batch:
                tx = decode_tx(raw_tx)
                tx_key = raw_tx.hex()
                if tx_key in seen:
                    continue
                seen.add(tx_key)
                ordered_results.append(tx)

        return ordered_results

    async def _run_round(self, round_id: int, tx_to_send: list[Any]) -> Result[list[Any]]:
        try:
            async with asyncio.TaskGroup() as task_group:
                ctx = self._build_round_context(round_id)
                spawn = self._task_spawner(task_group, ctx.tasks)

                spawn(ctx.router.recv_dispatcher())
                spawn(
                    ctx.router.route_broadcast_queue(
                        ctx.tpke_bcast_queue,
                        Channel.TPKE,
                        None,
                        broadcast=True,
                    )
                )
                spawn(
                    run_bkr93_acs(
                        params=CSParams(
                            sid=f"{ctx.sid}CS",
                            pid=ctx.pid,
                            N=ctx.n,
                            f=ctx.f,
                            leader=ctx.pid,
                        ),
                        crypto=self.crypto,
                        task_group=task_group,
                        spawn=spawn,
                        router=ctx.router,
                        coin_recvs=ctx.coin_recvs,
                        aba_recvs=ctx.aba_recvs,
                        rbc_recvs=ctx.rbc_recvs,
                        mempool=self.mempool,
                        round_id=ctx.round_id,
                        my_rbc_input=ctx.my_rbc_input,
                        output_queue=ctx.acs_output_queue,
                        logger=self.logger,
                    )
                )

                propose_queue: asyncio.Queue[bytes] = asyncio.Queue(1)
                propose_queue.put_nowait(encode_tx_batch([encode_tx(tx) for tx in tx_to_send]))
                block_task = spawn(
                    honeybadger_block(
                        ctx.pid,
                        ctx.n,
                        ctx.f,
                        self.crypto.enc_pk,
                        self.crypto.enc_sk,
                        propose_queue,
                        ctx.my_rbc_input,
                        ctx.acs_output_queue,
                        ctx.tpke_bcast_queue,
                        ctx.tpke_recv,
                        self.logger,
                    )
                )

                block = await asyncio.wait_for(block_task, timeout=self.config.round_timeout)
                self._cancel_round_tasks(ctx.tasks, keep={block_task})

            self.mempool.cleanup(round_id)
            return success(self._merge_block_batches(block))
        except TimeoutError:
            return self._round_failure("TIMEOUT", round_id, f"Round {round_id} exceeded timeout")
        except Exception as exc:
            code, message, details = self._classify_round_exception(round_id, exc)
            return self._round_failure(code, round_id, message, details)

    def _build_round_context(self, round_id: int) -> RoundContext:
        tpke_recv: asyncio.Queue[TpkeRecv] = asyncio.Queue()
        coin_recvs: list[asyncio.Queue[CoinRecv]] = [asyncio.Queue() for _ in range(self.common.N)]
        aba_recvs: list[asyncio.Queue[AbaRecv]] = [asyncio.Queue() for _ in range(self.common.N)]
        rbc_recvs: list[asyncio.Queue[RbcRecv]] = [asyncio.Queue() for _ in range(self.common.N)]
        return RoundContext(
            round_id=round_id,
            sid=f"{self.common.sid}:{round_id}",
            pid=self.common.pid,
            n=self.common.N,
            f=self.common.f,
            router=RoundProtocolRouter(
                round_id=round_id,
                num_nodes=self.common.N,
                transport=self.transport,
                inbound_queue=self.mailboxes.inbox(round_id),
                coin_recvs=coin_recvs,
                aba_recvs=aba_recvs,
                rbc_recvs=rbc_recvs,
                tpke_recv=tpke_recv,
                logger=self.logger,
            ),
            coin_recvs=coin_recvs,
            aba_recvs=aba_recvs,
            rbc_recvs=rbc_recvs,
            tpke_recv=tpke_recv,
            tpke_bcast_queue=asyncio.Queue(),
            my_rbc_input=asyncio.Queue(1),
            acs_output_queue=asyncio.Queue(1),
        )

    @staticmethod
    def _task_spawner(
        task_group: asyncio.TaskGroup, tasks: list[asyncio.Task[Any]]
    ) -> Callable[[Awaitable[Any]], asyncio.Task[Any]]:
        def spawn(coro: Awaitable[Any]) -> asyncio.Task[Any]:
            task = task_group.create_task(coro)
            tasks.append(task)
            return task

        return spawn

    @staticmethod
    def _cancel_round_tasks(
        tasks: list[asyncio.Task[Any]], keep: set[asyncio.Task[Any]] | None = None
    ) -> None:
        keep = keep or set()
        for task in tasks:
            if task in keep or task.done():
                continue
            task.cancel()

    @classmethod
    def _iter_leaf_exceptions(cls, exc: BaseException) -> Iterator[BaseException]:
        if isinstance(exc, BaseExceptionGroup):
            for nested in exc.exceptions:
                yield from cls._iter_leaf_exceptions(nested)
            return
        yield exc

    @classmethod
    def _classify_round_exception(
        cls, round_id: int, exc: Exception
    ) -> tuple[str, str, dict[str, Any]]:
        leaf_exceptions = list(cls._iter_leaf_exceptions(exc))
        classified = leaf_exceptions or [exc]

        for error_type, code, message in (
            (
                RoutingError,
                "ROUTING_ERROR",
                f"Round {round_id} failed due to a routing invariant violation",
            ),
            (
                SerializationError,
                "SERIALIZATION_ERROR",
                f"Round {round_id} failed due to an invalid protocol payload",
            ),
            (
                ProtocolInvariantError,
                "PROTOCOL_BUG",
                f"Round {round_id} violated a protocol invariant",
            ),
        ):
            for leaf in classified:
                if isinstance(leaf, error_type):
                    return (
                        code,
                        message,
                        {
                            "error": str(leaf),
                            "exception_type": type(leaf).__name__,
                        },
                    )

        first = classified[0]
        return (
            "INTERNAL_ERROR",
            f"Unexpected error in round {round_id}",
            {"error": str(first), "exception_type": type(first).__name__},
        )

    def _round_failure(
        self,
        code: str,
        round_id: int,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> Result[list[Any]]:
        extra = {"round": round_id, "error_code": code, "details": details or {}}
        if code == "TIMEOUT":
            self.logger.warning("Round timeout", extra=extra)
        else:
            self.logger.error(message, extra=extra)
        return failure(code, message, details)
