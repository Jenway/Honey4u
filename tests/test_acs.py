import asyncio

import pytest

from honey.acs.bkr93 import CSParams, commonsubset


@pytest.mark.asyncio
async def test_acs_single_round():
    """Test ACS with all nodes providing input"""
    N = 4
    f = 1
    sid = "test:acs:single"

    rbc_queues = [asyncio.Queue() for _ in range(N)]
    aba_input_queues = [asyncio.Queue(1) for _ in range(N)]
    aba_output_queues = [asyncio.Queue() for _ in range(N)]

    test_data = [f"data_from_node_{i}".encode() for i in range(N)]
    for i, data in enumerate(test_data):
        await rbc_queues[i].put(data)

    for j in range(N):
        await aba_output_queues[j].put(1)

    params = CSParams(sid=sid, pid=0, N=N, f=f, leader=0)
    result = await asyncio.wait_for(
        commonsubset(params, rbc_queues, aba_input_queues, aba_output_queues), timeout=5.0
    )

    assert len(result) == N
    assert result == tuple(test_data)


@pytest.mark.asyncio
async def test_acs_partial_participation():
    """Test ACS where f nodes don't provide input (simulating failure)"""
    N = 4
    f = 1
    sid = "test:acs:partial"

    rbc_queues = [asyncio.Queue() for _ in range(N)]
    aba_input_queues = [asyncio.Queue(1) for _ in range(N)]
    aba_output_queues = [asyncio.Queue() for _ in range(N)]

    for i in range(N - f):
        await rbc_queues[i].put(f"data_from_node_{i}".encode())

    for j in range(N):
        await aba_output_queues[j].put(1 if j < N - f else 0)

    params = CSParams(sid=sid, pid=0, N=N, f=f, leader=0)
    result = await asyncio.wait_for(
        commonsubset(params, rbc_queues, aba_input_queues, aba_output_queues), timeout=5.0
    )

    assert len(result) == N
    for j in range(N - f):
        assert result[j] is not None
    for j in range(N - f, N):
        assert result[j] is None


@pytest.mark.asyncio
async def test_acs_multiple_nodes_byzantine():
    """Test ACS with Byzantine nodes sending different data"""
    N = 4
    f = 1
    sid = "test:acs:byzantine"

    rbc_queues = [asyncio.Queue() for _ in range(N)]
    aba_input_queues = [asyncio.Queue(1) for _ in range(N)]
    aba_output_queues = [asyncio.Queue() for _ in range(N)]

    await rbc_queues[0].put(b"honest_data")

    for i in range(1, N):
        await rbc_queues[i].put(f"data_from_node_{i}".encode())

    for j in range(N):
        await aba_output_queues[j].put(1)

    params = CSParams(sid=sid, pid=0, N=N, f=f, leader=0)
    result = await asyncio.wait_for(
        commonsubset(params, rbc_queues, aba_input_queues, aba_output_queues), timeout=5.0
    )

    assert len(result) == N
    assert result[0] == b"honest_data"
    for i in range(1, N):
        assert result[i] == f"data_from_node_{i}".encode()
