import asyncio
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable, Coroutine, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

import honey_native
from honey_acs.data.broadcast_mempool import BroadcastMempool
from honey_acs.hb.bkr93 import CSParams, run_bkr93_acs_with_send
from honey_runtime.infra.ledger import LedgerRecorder, build_sqlite_ledger_sink
from honey_runtime.routing.mailbox import NodeMailboxRouter
from honey_runtime.routing.round_router import (
    AbaRecv,
    CoinRecv,
    RbcRecv,
    RoundProtocolRouter,
    TpkeRecv,
)
from honey_runtime.transport import Transport
from honey_shared.exceptions import ProtocolInvariantError, RoutingError, SerializationError
from honey_shared.messages import (
    Channel,
    ProtocolEnvelope,
    ProtocolMessage,
    decode_block,
    decode_tx_batch,
    merge_tx_batches_bytes,
)
from honey_shared.params import CommonParams, CryptoParams, HBConfig
from honey_shared.results import Failure, Result, Success, failure, success
from honey_shared.telemetry import METRICS, log_event, timed_metric

from honey_legacy_node.honeybadger.block import honeybadger_block


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


@dataclass(frozen=True)
class PendingRoundBatch:
    proposal_payload: bytes
    tx_ids: tuple[str, ...]


@dataclass(frozen=True)
class CommittedBlock:
    payload: bytes
    tx_count: int

    @classmethod
    def from_block_batches(cls, block_batches: tuple[bytes, ...]) -> CommittedBlock:
        payload = merge_tx_batches_bytes(block_batches)
        return cls(payload=payload, tx_count=len(decode_tx_batch(payload)))

    def decode(self) -> list[Any]:
        return decode_block(self.payload)


class AcsHost(Protocol):
    def start_round(self, *, round_id: int, sid: str, proposal_input: bytes | str) -> None: ...

    def push_inbound_batch(
        self,
        items: list[tuple[int, int, str, int | None, object]],
    ) -> int: ...

    def pull_outbound_batch(self, limit: int = 128) -> list[dict[str, object]]: ...

    def abort_round(self, round_id: int) -> None: ...

    def outbound_ready(self) -> bool: ...

    def outbound_wait_fd(self) -> int: ...


class HoneyBadgerBFT:
    def __init__(
        self,
        common_params: CommonParams,
        crypto_params: CryptoParams,
        transport: Transport,
        config: HBConfig | None = None,
        acs_host: AcsHost | None = None,
    ):
        self.common = common_params
        self.crypto = crypto_params
        self.transport = transport
        self.config = config or HBConfig()
        self._acs_host = acs_host
        self.logger = self._build_logger(common_params.pid)
        self._ledger = self._build_ledger_recorder()
        self.mailboxes = NodeMailboxRouter(self.transport, self.logger)
        self.round = 0
        self._rust_tx_pool = honey_native.TxPool()
        self._next_tx_seq = 0
        self._active_batch: PendingRoundBatch | None = None
        self.mempool = BroadcastMempool(max_size=1000, expire_rounds=self.config.pool_expire_rounds)
        self.K = self.config.max_rounds
        self.txcnt = 0
        self.round_build_latencies: list[float] = []
        self.round_latencies: list[float] = []
        self.round_wall_latencies: list[float] = []
        self.round_proposed_counts: list[int] = []
        self.round_delivered_counts: list[int] = []
        self.origin_tx_latencies: list[float] = []
        self.origin_tx_latencies_by_round: list[tuple[float, ...]] = []
        self.block_digests: list[str] = []
        self.chain_digest: str | None = self._ledger.chain_digest
        self.ledger_path: str | None = self._ledger.ledger_path
        self._tracked_submission_times_ns: dict[bytes, deque[int]] = {}

    def _build_logger(self, pid: int) -> logging.LoggerAdapter:
        return logging.LoggerAdapter(logging.getLogger("honey.hb"), extra={"node": pid})

    def _protocol_name(self) -> str:
        return "hb"

    def _build_ledger_recorder(self) -> LedgerRecorder:
        sink = None
        if self.config.enable_ledger_persistence and self.config.ledger_dir is not None:
            sink = build_sqlite_ledger_sink(
                self.config.ledger_dir,
                sid=str(self.common.sid),
                protocol=self._protocol_name(),
                pid=self.common.pid,
            )
        return LedgerRecorder(
            sid=str(self.common.sid),
            pid=self.common.pid,
            protocol=self._protocol_name(),
            sink=sink,
        )

    def submit_tx_json_str(
        self,
        tx: str,
        *,
        track_latency: bool = False,
        submitted_at_ns: int | None = None,
    ) -> None:
        tx_id = self._allocate_tx_id()
        payload = honey_native.encode_json_string(tx)
        self._rust_tx_pool.push(tx_id, payload)
        self._record_submission(
            payload, track_latency=track_latency, submitted_at_ns=submitted_at_ns
        )

    def submit_tx_bytes(
        self,
        payload: bytes,
        *,
        track_latency: bool = False,
        submitted_at_ns: int | None = None,
    ) -> None:
        tx_id = self._allocate_tx_id()
        self._rust_tx_pool.push(tx_id, payload)
        self._record_submission(
            payload, track_latency=track_latency, submitted_at_ns=submitted_at_ns
        )

    def _record_submission(
        self,
        payload: bytes,
        *,
        track_latency: bool,
        submitted_at_ns: int | None,
    ) -> None:
        if not track_latency:
            return
        tracked = self._tracked_submission_times_ns.setdefault(payload, deque())
        tracked.append(submitted_at_ns if submitted_at_ns is not None else time.time_ns())

    async def run(self) -> None:
        mailbox_task = asyncio.create_task(self.mailboxes.run())
        log_event(self.logger, logging.INFO, "hb_start", sid=self.common.sid, max_rounds=self.K)
        await asyncio.sleep(0)
        if mailbox_task.done():
            await mailbox_task

        try:
            try:
                while True:
                    if mailbox_task.done():
                        await mailbox_task

                    round_id = self.round
                    self.mailboxes.inbox(round_id)

                    round_wall_start = time.perf_counter()
                    round_build_start = round_wall_start
                    batch = self._build_round_batch()
                    self.round_build_latencies.append(time.perf_counter() - round_build_start)
                    if batch is None:
                        self.round_build_latencies.pop()
                        await asyncio.sleep(0.1)
                        continue

                    self._active_batch = batch
                    METRICS.increment("hb.round.started", node=self.common.pid)
                    log_event(
                        self.logger,
                        logging.DEBUG,
                        "round_start",
                        round=round_id,
                        batch_size=len(batch.tx_ids),
                    )
                    round_start = time.perf_counter()
                    with timed_metric("hb.round.seconds", node=self.common.pid, round=round_id):
                        round_result = await self._run_round(round_id, batch)
                    self.round_latencies.append(time.perf_counter() - round_start)
                    self.round_wall_latencies.append(time.perf_counter() - round_wall_start)

                    self._apply_round_result(round_id, batch, round_result)
                    self._active_batch = None
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
        finally:
            self._ledger.close()

    def _apply_round_result(
        self, round_id: int, batch: PendingRoundBatch, round_result: Result[CommittedBlock]
    ) -> None:
        self.round_proposed_counts.append(len(batch.tx_ids))

        if isinstance(round_result, Success):
            committed = round_result.value
            tx_cnt = committed.tx_count
            delivered_at_ns = time.time_ns()
            delivered_txs = decode_tx_batch(committed.payload)
            self.txcnt += tx_cnt
            origin_latencies = tuple(
                self._record_origin_tx_latencies(delivered_txs, delivered_at_ns=delivered_at_ns)
            )
            self.round_delivered_counts.append(tx_cnt)
            self.origin_tx_latencies_by_round.append(origin_latencies)
            ledger_record = self._ledger.append_block(
                round_id=round_id,
                block_payload=committed.payload,
                tx_count=tx_cnt,
                delivered_at_ns=delivered_at_ns,
            )
            self.block_digests.append(ledger_record.block_digest)
            self.chain_digest = ledger_record.chain_digest
            METRICS.increment("hb.round.succeeded", node=self.common.pid)
            METRICS.increment("hb.tx.delivered", tx_cnt, node=self.common.pid)
            self.logger.info(
                f"Delivered ACS Block in Round {round_id} with {tx_cnt} TXs",
                extra={"round": round_id, "tx_count": tx_cnt},
            )

            cast(Any, self._rust_tx_pool).resolve_delivery(list(batch.tx_ids), committed.payload)
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

        if batch.tx_ids:
            self._rust_tx_pool.requeue(list(batch.tx_ids))

    def _finish_round(self, round_id: int) -> None:
        self.mailboxes.close_round(round_id)

    def _record_origin_tx_latencies(
        self,
        delivered_txs: list[bytes],
        *,
        delivered_at_ns: int | None = None,
    ) -> list[float]:
        delivered_at_ns = delivered_at_ns if delivered_at_ns is not None else time.time_ns()
        round_latencies: list[float] = []
        for tx_key in delivered_txs:
            submission_times = self._tracked_submission_times_ns.get(tx_key)
            if not submission_times:
                continue
            submitted_at_ns = submission_times.popleft()
            if not submission_times:
                self._tracked_submission_times_ns.pop(tx_key, None)
            latency = max(0.0, (delivered_at_ns - submitted_at_ns) / 1_000_000_000)
            self.origin_tx_latencies.append(latency)
            round_latencies.append(latency)
        return round_latencies

    @classmethod
    def _merge_block_batches(cls, block: tuple[bytes, ...]) -> CommittedBlock:
        return CommittedBlock.from_block_batches(block)

    @staticmethod
    def _drain_queue_batch[T](
        queue: asyncio.Queue[T], first_item: T, *, limit: int = 64
    ) -> list[T]:
        items = [first_item]
        while len(items) < limit:
            try:
                items.append(queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return items

    def _abort_acs_host_round(self, round_id: int) -> None:
        if self._acs_host is None:
            return
        with suppress(Exception):
            self._acs_host.abort_round(round_id)

    @staticmethod
    def _acs_host_failure(round_id: int, event: dict[str, object]) -> RuntimeError:
        exception_type = str(event.get("exception_type", "RuntimeError"))
        error = str(event.get("error", "ACS host round failed"))
        return RuntimeError(f"ACS host round {round_id} failed with {exception_type}: {error}")

    async def _send_acs_host_event(
        self,
        round_id: int,
        event: dict[str, object],
    ) -> None:
        await self.transport.send(
            int(event["recipient"]),
            ProtocolEnvelope(
                round_id=round_id,
                channel=Channel(str(event["channel"])),
                instance_id=cast(int | None, event.get("instance_id")),
                message=cast(ProtocolMessage, event["message"]),
            ),
        )

    async def _wait_for_acs_host_outbound(self, host: AcsHost) -> None:
        if host.outbound_ready():
            return

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        wait_fd = host.outbound_wait_fd()

        def _notify_ready() -> None:
            if not future.done():
                future.set_result(None)

        loop.add_reader(wait_fd, _notify_ready)
        try:
            if host.outbound_ready():
                return
            await future
        finally:
            loop.remove_reader(wait_fd)

    async def _run_hosted_hb_acs_round(self, ctx: RoundContext) -> None:
        host = self._acs_host
        if host is None:
            raise RuntimeError("ACS host bridge is not configured")

        round_started = asyncio.Event()

        async def start_round() -> None:
            proposal_input = await ctx.my_rbc_input.get()
            host.start_round(
                round_id=ctx.round_id,
                sid=ctx.sid,
                proposal_input=proposal_input,
            )
            round_started.set()

        async def forward_queue(
            source: asyncio.Queue[tuple[int, object]],
            *,
            channel: Channel,
            instance_id: int,
        ) -> None:
            await round_started.wait()
            while True:
                sender, message = await source.get()
                batch = self._drain_queue_batch(source, (sender, message))
                host.push_inbound_batch(
                    [
                        (item_sender, ctx.round_id, channel.value, instance_id, item_message)
                        for item_sender, item_message in batch
                    ]
                )

        async def pump_outbound() -> None:
            await round_started.wait()
            while True:
                if not host.outbound_ready():
                    await self._wait_for_acs_host_outbound(host)
                    continue
                for event in host.pull_outbound_batch(256):
                    kind = str(event["kind"])
                    if kind == "send":
                        await self._send_acs_host_event(ctx.round_id, event)
                        continue
                    if kind == "decision":
                        ctx.acs_output_queue.put_nowait(
                            tuple(cast(list[bytes | None], event["selected_payloads"]))
                        )
                        return
                    if kind == "failure":
                        raise self._acs_host_failure(ctx.round_id, event)
                    if kind == "carryovers":
                        continue
                    raise ProtocolInvariantError(f"unexpected ACS host event kind: {kind}")

        try:
            async with asyncio.TaskGroup() as task_group:
                bridge_tasks: list[asyncio.Task[Any]] = []
                spawn_bridge = self._task_spawner(task_group, bridge_tasks)
                spawn_bridge(start_round())
                for instance_id, queue in enumerate(ctx.coin_recvs):
                    spawn_bridge(
                        forward_queue(
                            queue,
                            channel=Channel.ACS_COIN,
                            instance_id=instance_id,
                        )
                    )
                for instance_id, queue in enumerate(ctx.aba_recvs):
                    spawn_bridge(
                        forward_queue(
                            queue,
                            channel=Channel.ACS_ABA,
                            instance_id=instance_id,
                        )
                    )
                for instance_id, queue in enumerate(ctx.rbc_recvs):
                    spawn_bridge(
                        forward_queue(
                            queue,
                            channel=Channel.ACS_RBC,
                            instance_id=instance_id,
                        )
                    )
                outbound_task = spawn_bridge(pump_outbound())
                await outbound_task
                self._cancel_round_tasks(bridge_tasks, keep={outbound_task})
        except asyncio.CancelledError:
            self._abort_acs_host_round(ctx.round_id)
            raise
        except Exception:
            self._abort_acs_host_round(ctx.round_id)
            raise

    async def _run_round(self, round_id: int, batch: PendingRoundBatch) -> Result[CommittedBlock]:
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
                if self._acs_host is None:
                    spawn(
                        run_bkr93_acs_with_send(
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
                            coin_recvs=ctx.coin_recvs,
                            aba_recvs=ctx.aba_recvs,
                            rbc_recvs=ctx.rbc_recvs,
                            mempool=self.mempool,
                            round_id=ctx.round_id,
                            my_rbc_input=ctx.my_rbc_input,
                            output_queue=ctx.acs_output_queue,
                            logger=self.logger,
                            send=self._send_round_message(round_id),
                            output_mode="payloads",
                        )
                    )
                else:
                    spawn(self._run_hosted_hb_acs_round(ctx))

                propose_queue: asyncio.Queue[bytes] = asyncio.Queue(1)
                propose_queue.put_nowait(self._proposal_payload_for_active_batch(batch))
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
            return success(await asyncio.to_thread(self._merge_block_batches, block))
        except TimeoutError:
            return self._round_failure("TIMEOUT", round_id, f"Round {round_id} exceeded timeout")
        except Exception as exc:
            code, message, details = self._classify_round_exception(round_id, exc)
            return self._round_failure(code, round_id, message, details)

    def _allocate_tx_id(self) -> str:
        tx_id = f"{self.common.pid}:{self._next_tx_seq}"
        self._next_tx_seq += 1
        return tx_id

    def _send_round_message(
        self, round_id: int
    ) -> Callable[[int, Channel, int | None, ProtocolMessage], Awaitable[None]]:
        async def send(
            recipient: int,
            channel: Channel,
            instance_id: int | None,
            message: ProtocolMessage,
        ) -> None:
            await self.transport.send(
                recipient,
                ProtocolEnvelope(
                    round_id=round_id,
                    channel=channel,
                    instance_id=instance_id,
                    message=message,
                ),
            )

        return send

    def _build_round_batch(self) -> PendingRoundBatch | None:
        tx_ids, proposal_payload = self._rust_tx_pool.pop_batch(
            self.config.batch_size,
            self.config.rust_tx_pool_max_bytes,
        )
        if not tx_ids:
            return None

        return PendingRoundBatch(
            proposal_payload=proposal_payload,
            tx_ids=tuple(tx_ids),
        )

    def _proposal_payload_for_active_batch(self, batch: PendingRoundBatch) -> bytes:
        if self._active_batch is None:
            return batch.proposal_payload
        return self._active_batch.proposal_payload

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
            task = task_group.create_task(cast(Coroutine[Any, Any, Any], coro))
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
    ) -> Result[CommittedBlock]:
        details = details or {}
        extra = {"round": round_id, "error_code": code, "details": details}
        if code == "TIMEOUT":
            self.logger.warning("Round timeout", extra=extra)
        else:
            detail_suffix = ""
            if details:
                exception_type = details.get("exception_type")
                error = details.get("error")
                if exception_type or error:
                    detail_suffix = f" [{exception_type}: {error}]"
            self.logger.error(f"{message}{detail_suffix}", extra=extra)
        return failure(code, message, details)
