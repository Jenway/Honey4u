from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from honey.consensus.dumbo.core import DumboBFT
from honey.consensus.honeybadger.core import HoneyBadgerBFT
from honey.support.params import CommonParams, CryptoParams, HBConfig


@dataclass(frozen=True, slots=True)
class NodeBootstrapPlan:
    protocol: str
    sid: str
    pid: int
    N: int
    f: int
    leader: int
    max_rounds: int
    transport_handle_type: str
    commit_sink_type: str


@dataclass(frozen=True, slots=True)
class HBNodeBootstrapPlan(NodeBootstrapPlan):
    pass


@dataclass(frozen=True, slots=True)
class DumboNodeBootstrapPlan(NodeBootstrapPlan):
    pass


def _ensure_transport_contract(transport_handle: Any) -> None:
    for method_name in ("send", "recv"):
        method = getattr(transport_handle, method_name, None)
        if not callable(method):
            raise ValueError(f"transport_handle must define callable {method_name}()")


def _emit_commit(
    commit_sink: Any,
    *,
    round_id: int,
    payload: bytes,
    tx_count: int,
) -> None:
    commit = getattr(commit_sink, "commit", None)
    if not callable(commit):
        return
    commit(round_id=round_id, payload=payload, tx_count=tx_count)


def _install_commit_hook(node: HoneyBadgerBFT | DumboBFT, commit_sink: Any) -> None:
    ledger = node._ledger
    append_block = ledger.append_block

    def wrapped_append_block(
        *,
        round_id: int,
        block_payload: bytes,
        tx_count: int,
        delivered_at_ns: int,
    ) -> Any:
        record = append_block(
            round_id=round_id,
            block_payload=block_payload,
            tx_count=tx_count,
            delivered_at_ns=delivered_at_ns,
        )
        _emit_commit(commit_sink, round_id=round_id, payload=block_payload, tx_count=tx_count)
        return record

    ledger.append_block = wrapped_append_block


def _coerce_common(common: CommonParams | Mapping[str, Any]) -> CommonParams:
    if isinstance(common, CommonParams):
        return common
    return CommonParams(
        sid=common["sid"],
        pid=int(common["pid"]),
        N=int(common["N"]),
        f=int(common["f"]),
        leader=int(common["leader"]),
    )


def _coerce_config(config: HBConfig | Mapping[str, Any] | None) -> HBConfig:
    if config is None:
        return HBConfig()
    if isinstance(config, HBConfig):
        return config
    return HBConfig(**dict(config))


def _build_plan(
    *,
    protocol: str,
    common: CommonParams | Mapping[str, Any],
    transport_handle: Any,
    commit_sink: Any,
    config: HBConfig | Mapping[str, Any] | None,
) -> NodeBootstrapPlan:
    resolved_common = _coerce_common(common)
    resolved_config = _coerce_config(config)
    _ensure_transport_contract(transport_handle)
    return NodeBootstrapPlan(
        protocol=protocol,
        sid=str(resolved_common.sid),
        pid=resolved_common.pid,
        N=resolved_common.N,
        f=resolved_common.f,
        leader=resolved_common.leader,
        max_rounds=resolved_config.max_rounds,
        transport_handle_type=type(transport_handle).__name__,
        commit_sink_type=type(commit_sink).__name__,
    )


def plan_hb_node(
    common: CommonParams | Mapping[str, Any],
    crypto: CryptoParams | None,
    transport_handle: Any,
    commit_sink: Any,
    config: HBConfig | Mapping[str, Any] | None,
) -> HBNodeBootstrapPlan:
    del crypto
    plan = _build_plan(
        protocol="hb",
        common=common,
        transport_handle=transport_handle,
        commit_sink=commit_sink,
        config=config,
    )
    return HBNodeBootstrapPlan(
        protocol=plan.protocol,
        sid=plan.sid,
        pid=plan.pid,
        N=plan.N,
        f=plan.f,
        leader=plan.leader,
        max_rounds=plan.max_rounds,
        transport_handle_type=plan.transport_handle_type,
        commit_sink_type=plan.commit_sink_type,
    )


def plan_dumbo_node(
    common: CommonParams | Mapping[str, Any],
    crypto: CryptoParams | None,
    transport_handle: Any,
    commit_sink: Any,
    config: HBConfig | Mapping[str, Any] | None,
) -> DumboNodeBootstrapPlan:
    del crypto
    plan = _build_plan(
        protocol="dumbo",
        common=common,
        transport_handle=transport_handle,
        commit_sink=commit_sink,
        config=config,
    )
    return DumboNodeBootstrapPlan(
        protocol=plan.protocol,
        sid=plan.sid,
        pid=plan.pid,
        N=plan.N,
        f=plan.f,
        leader=plan.leader,
        max_rounds=plan.max_rounds,
        transport_handle_type=plan.transport_handle_type,
        commit_sink_type=plan.commit_sink_type,
    )


async def _run_protocol_node(
    protocol: str,
    common: CommonParams | Mapping[str, Any],
    crypto: CryptoParams,
    transport_handle: Any,
    commit_sink: Any,
    config: HBConfig | Mapping[str, Any] | None,
    before_run: Callable[[HoneyBadgerBFT | DumboBFT], None] | None = None,
) -> HoneyBadgerBFT | DumboBFT:
    _ensure_transport_contract(transport_handle)
    resolved_common = _coerce_common(common)
    resolved_config = _coerce_config(config)
    node_cls = DumboBFT if protocol == "dumbo" else HoneyBadgerBFT
    node = node_cls(resolved_common, crypto, transport_handle, config=resolved_config)
    _install_commit_hook(node, commit_sink)
    if before_run is not None:
        before_run(node)
    await node.run()
    return node


async def run_hb_node(
    common: CommonParams | Mapping[str, Any],
    crypto: CryptoParams,
    transport_handle: Any,
    commit_sink: Any,
    config: HBConfig | Mapping[str, Any] | None,
    before_run: Callable[[HoneyBadgerBFT], None] | None = None,
) -> HoneyBadgerBFT:
    node = await _run_protocol_node(
        "hb",
        common,
        crypto,
        transport_handle,
        commit_sink,
        config,
        before_run=before_run,
    )
    return cast(HoneyBadgerBFT, node)


def start_hb_node(
    common: CommonParams | Mapping[str, Any],
    crypto: CryptoParams,
    transport_handle: Any,
    commit_sink: Any,
    config: HBConfig | Mapping[str, Any] | None,
    before_run: Callable[[HoneyBadgerBFT], None] | None = None,
) -> HoneyBadgerBFT:
    return asyncio.run(
        run_hb_node(
            common,
            crypto,
            transport_handle,
            commit_sink,
            config,
            before_run=before_run,
        )
    )


async def run_dumbo_node(
    common: CommonParams | Mapping[str, Any],
    crypto: CryptoParams,
    transport_handle: Any,
    commit_sink: Any,
    config: HBConfig | Mapping[str, Any] | None,
    before_run: Callable[[DumboBFT], None] | None = None,
) -> DumboBFT:
    node = await _run_protocol_node(
        "dumbo",
        common,
        crypto,
        transport_handle,
        commit_sink,
        config,
        before_run=cast(Callable[[HoneyBadgerBFT | DumboBFT], None] | None, before_run),
    )
    return cast(DumboBFT, node)


def start_dumbo_node(
    common: CommonParams | Mapping[str, Any],
    crypto: CryptoParams,
    transport_handle: Any,
    commit_sink: Any,
    config: HBConfig | Mapping[str, Any] | None,
    before_run: Callable[[DumboBFT], None] | None = None,
) -> DumboBFT:
    return asyncio.run(
        run_dumbo_node(
            common,
            crypto,
            transport_handle,
            commit_sink,
            config,
            before_run=before_run,
        )
    )
