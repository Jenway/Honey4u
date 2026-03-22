"""Integration tests for Binary Agreement protocol"""

import asyncio

import pytest

from honeybadgerbft.binaryagreement import BAParams, binaryagreement


class MockCoin:
    """Mock coin function for testing BA"""

    def __init__(self, values: dict = None):
        """
        :param values: dict mapping round -> coin value (0 or 1)
                      If not provided, alternates between 0 and 1
        """
        self.values = values or {}
        self.round_counter = {}

    async def __call__(self, round_num: int) -> int:
        """Get coin value for a round"""
        if round_num in self.values:
            return self.values[round_num]
        # Default: alternate between 0 and 1
        return round_num % 2


@pytest.mark.asyncio
async def test_ba_agree_on_zero():
    """Test Binary Agreement when all nodes input 0"""
    N = 4
    f = 1
    sid = "test:ba:zero"

    # Create queues for each node
    input_queues = [asyncio.Queue(1) for _ in range(N)]
    decide_queues = [asyncio.Queue(1) for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]
    send_queues = [asyncio.Queue() for _ in range(N)]

    # All nodes input 0
    for i in range(N):
        await input_queues[i].put(0)

    # Create mock coin for this test
    coin = MockCoin({0: 0})  # Round 0 returns 0

    # Create BA tasks
    ba_tasks = []
    for i in range(N):
        params = BAParams(sid=sid, pid=i, N=N, f=f, leader=0)
        task = asyncio.create_task(
            binaryagreement(
                params,
                coin,  # Coin function
                input_queues[i],
                decide_queues[i],
                recv_queues[i],
                send_queues[i],
            )
        )
        ba_tasks.append(task)

    # Message router
    async def msg_router(sender_idx: int):
        while True:
            try:
                try:
                    recipient, message = send_queues[sender_idx].get_nowait()
                    await recv_queues[recipient].put((sender_idx, message))
                except asyncio.QueueEmpty:
                    await asyncio.sleep(0.001)
            except asyncio.CancelledError:
                break

    routers = [asyncio.create_task(msg_router(i)) for i in range(N)]

    try:
        # Run BA with timeout
        await asyncio.wait_for(asyncio.gather(*ba_tasks), timeout=10.0)

        # All nodes should have decided 0
        for i in range(N):
            result = decide_queues[i].get_nowait()
            assert result == 0, f"Node {i} decided {result}, expected 0"

    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_ba_agree_on_one():
    """Test Binary Agreement when all nodes input 1"""
    N = 4
    f = 1
    sid = "test:ba:one"

    input_queues = [asyncio.Queue(1) for _ in range(N)]
    decide_queues = [asyncio.Queue(1) for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]
    send_queues = [asyncio.Queue() for _ in range(N)]

    # All nodes input 1
    for i in range(N):
        await input_queues[i].put(1)

    coin = MockCoin({0: 1})  # Round 0 returns 1

    ba_tasks = []
    for i in range(N):
        params = BAParams(sid=sid, pid=i, N=N, f=f, leader=0)
        task = asyncio.create_task(
            binaryagreement(
                params,
                coin,
                input_queues[i],
                decide_queues[i],
                recv_queues[i],
                send_queues[i],
            )
        )
        ba_tasks.append(task)

    async def msg_router(sender_idx: int):
        while True:
            try:
                try:
                    recipient, message = send_queues[sender_idx].get_nowait()
                    await recv_queues[recipient].put((sender_idx, message))
                except asyncio.QueueEmpty:
                    await asyncio.sleep(0.001)
            except asyncio.CancelledError:
                break

    routers = [asyncio.create_task(msg_router(i)) for i in range(N)]

    try:
        await asyncio.wait_for(asyncio.gather(*ba_tasks), timeout=10.0)

        for i in range(N):
            result = decide_queues[i].get_nowait()
            assert result == 1, f"Node {i} decided {result}, expected 1"

    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_ba_mixed_input():
    """Test Binary Agreement with mixed input (some 0s, some 1s)"""
    N = 4
    f = 1
    sid = "test:ba:mixed"

    input_queues = [asyncio.Queue(1) for _ in range(N)]
    decide_queues = [asyncio.Queue(1) for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]
    send_queues = [asyncio.Queue() for _ in range(N)]

    # Some nodes input 0, others input 1
    # With N=4, f=1: we need at least 3 nodes to have same input
    # Let's give 3 nodes 0, 1 node 1
    for i in range(3):
        await input_queues[i].put(0)
    await input_queues[3].put(1)

    # Coin should be 0 to help consensus
    coin = MockCoin({0: 0})

    ba_tasks = []
    for i in range(N):
        params = BAParams(sid=sid, pid=i, N=N, f=f, leader=0)
        task = asyncio.create_task(
            binaryagreement(
                params,
                coin,
                input_queues[i],
                decide_queues[i],
                recv_queues[i],
                send_queues[i],
            )
        )
        ba_tasks.append(task)

    async def msg_router(sender_idx: int):
        while True:
            try:
                try:
                    recipient, message = send_queues[sender_idx].get_nowait()
                    await recv_queues[recipient].put((sender_idx, message))
                except asyncio.QueueEmpty:
                    await asyncio.sleep(0.001)
            except asyncio.CancelledError:
                break

    routers = [asyncio.create_task(msg_router(i)) for i in range(N)]

    try:
        await asyncio.wait_for(asyncio.gather(*ba_tasks), timeout=10.0)

        # All nodes should decide the same value
        decisions = []
        for i in range(N):
            result = decide_queues[i].get_nowait()
            decisions.append(result)

        # All should be the same
        assert all(d == decisions[0] for d in decisions), f"Nodes didn't agree: {decisions}"

    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass
