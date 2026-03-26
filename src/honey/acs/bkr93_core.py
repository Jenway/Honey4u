from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from honey.support.exceptions import ProtocolInvariantError


@dataclass(frozen=True)
class ProvideAbaInput:
    index: int
    value: int


@dataclass
class Bkr93State:
    n: int
    f: int
    aba_input_sent: list[bool]
    aba_outcomes: list[int | None]
    rbc_values: list[Any | None]


def new_state(n: int, f: int) -> Bkr93State:
    return Bkr93State(
        n=n,
        f=f,
        aba_input_sent=[False] * n,
        aba_outcomes=[None] * n,
        rbc_values=[None] * n,
    )


def on_rbc_delivered(state: Bkr93State, index: int, value: Any) -> list[ProvideAbaInput]:
    state.rbc_values[index] = value
    return _provide_aba_input(state, index, 1)


def on_aba_decided(state: Bkr93State, index: int, value: int) -> list[ProvideAbaInput]:
    state.aba_outcomes[index] = value

    if count_ones(state) < state.n - state.f:
        return []

    effects: list[ProvideAbaInput] = []
    for k in range(state.n):
        effects.extend(_provide_aba_input(state, k, 0))
    return effects


def count_ones(state: Bkr93State) -> int:
    return sum(1 for outcome in state.aba_outcomes if outcome == 1)


def aba_complete(state: Bkr93State) -> bool:
    return all(outcome is not None for outcome in state.aba_outcomes)


def output_ready(state: Bkr93State) -> bool:
    if not aba_complete(state):
        return False
    if count_ones(state) < state.n - state.f:
        return False
    return all(
        outcome != 1 or state.rbc_values[index] is not None
        for index, outcome in enumerate(state.aba_outcomes)
    )


def build_output(state: Bkr93State) -> tuple[Any | None, ...]:
    if not output_ready(state):
        raise ProtocolInvariantError("BKR93 output is not ready")

    return tuple(
        value if outcome == 1 else None
        for value, outcome in zip(state.rbc_values, state.aba_outcomes, strict=True)
    )


def _provide_aba_input(state: Bkr93State, index: int, value: int) -> list[ProvideAbaInput]:
    if state.aba_input_sent[index]:
        return []
    state.aba_input_sent[index] = True
    return [ProvideAbaInput(index=index, value=value)]
