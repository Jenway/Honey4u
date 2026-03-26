from honey.acs.bkr93_core import (
    ProvideAbaInput,
    aba_complete,
    build_output,
    count_ones,
    new_state,
    on_aba_decided,
    on_rbc_delivered,
    output_ready,
)


def test_bkr93_core_rbc_delivery_triggers_single_aba_one() -> None:
    state = new_state(4, 1)

    effects = on_rbc_delivered(state, 2, b"payload")

    assert effects == [ProvideAbaInput(index=2, value=1)]
    assert state.rbc_values[2] == b"payload"
    assert on_rbc_delivered(state, 2, b"newer") == []


def test_bkr93_core_threshold_of_ones_fills_missing_aba_inputs() -> None:
    state = new_state(4, 1)
    on_rbc_delivered(state, 0, b"a")
    on_rbc_delivered(state, 2, b"c")

    assert on_aba_decided(state, 0, 1) == []
    assert on_aba_decided(state, 1, 1) == []
    effects = on_aba_decided(state, 2, 1)

    assert count_ones(state) == 3
    assert effects == [
        ProvideAbaInput(index=1, value=0),
        ProvideAbaInput(index=3, value=0),
    ]


def test_bkr93_core_output_requires_all_decisions_and_selected_rbc_values() -> None:
    state = new_state(4, 1)

    on_rbc_delivered(state, 0, b"a")
    on_rbc_delivered(state, 1, b"b")
    on_rbc_delivered(state, 2, b"c")
    on_aba_decided(state, 0, 1)
    on_aba_decided(state, 1, 1)
    on_aba_decided(state, 2, 1)

    assert aba_complete(state) is False
    assert output_ready(state) is False

    on_aba_decided(state, 3, 0)

    assert aba_complete(state) is True
    assert output_ready(state) is True
    assert build_output(state) == (b"a", b"b", b"c", None)
