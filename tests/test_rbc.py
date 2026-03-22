import asyncio
import json

import pytest

from honeybadgerbft.params import CommonParams
from honeybadgerbft.reliablebroadcast import reliablebroadcast


@pytest.mark.asyncio
async def test_rbc_single_leader():
    """Test RBC with one leader broadcasting to others"""
    N = 4
    f = 1
    leader = 0
    sid = "test:rbc:single"

    # Create input/output queues for each node
    input_queues = [asyncio.Queue() for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]
    send_queues = [asyncio.Queue() for _ in range(N)]

    test_data = b"hello world"

    # Put data in leader's input queue
    await input_queues[leader].put(test_data)

    # Create RBC params for each node
    tasks = []
    for i in range(N):
        params = CommonParams(sid=sid, pid=i, N=N, f=f, leader=leader)
        task = asyncio.create_task(
            reliablebroadcast(
                params,
                input_queues[i],  # Only leader uses this
                recv_queues[i],
                send_queues,
            )
        )
        tasks.append(task)

    # Helper to route messages between nodes
    async def msg_router(sender_idx: int, recv_queues: list):
        """Route messages from sender to all receivers"""
        while True:
            try:
                # Non-blocking check if message available
                try:
                    recipient, message = send_queues[sender_idx].get_nowait()
                    await recv_queues[recipient].put((sender_idx, message))
                except asyncio.QueueEmpty:
                    await asyncio.sleep(0.001)
            except asyncio.CancelledError:
                break

    # Start message routers for each node
    routers = []
    for i in range(N):
        router = asyncio.create_task(msg_router(i, recv_queues))
        routers.append(router)

    # Wait for RBC to complete with timeout
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)

        # Leader should get original data
        assert results[leader] == test_data

        # All other nodes should get the same data
        for i in range(N):
            if i != leader:
                assert results[i] == test_data

    finally:
        # Clean up routers
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_rbc_different_leaders():
    """Test RBC where each node is a leader"""
    N = 4
    f = 1

    for leader in range(N):
        sid = f"test:rbc:leader{leader}"

        # Create queues
        input_queues = [asyncio.Queue() for _ in range(N)]
        recv_queues = [asyncio.Queue() for _ in range(N)]
        send_queues = [asyncio.Queue() for _ in range(N)]

        test_data = f"data_from_leader_{leader}".encode()
        await input_queues[leader].put(test_data)

        # Create RBC tasks
        tasks = []
        for i in range(N):
            params = CommonParams(sid=sid, pid=i, N=N, f=f, leader=leader)
            task = asyncio.create_task(
                reliablebroadcast(params, input_queues[i], recv_queues[i], send_queues)
            )
            tasks.append(task)

        # Message router
        async def msg_router(sender_idx: int, send_queues: list, recv_queues: list):
            while True:
                try:
                    try:
                        recipient, message = send_queues[sender_idx].get_nowait()
                        await recv_queues[recipient].put((sender_idx, message))
                    except asyncio.QueueEmpty:
                        await asyncio.sleep(0.001)
                except asyncio.CancelledError:
                    break

        routers = []
        for i in range(N):
            router = asyncio.create_task(msg_router(i, send_queues, recv_queues))
            routers.append(router)

        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)

            # All nodes should get same data from leader
            for result in results:
                assert result == test_data

        finally:
            for router in routers:
                router.cancel()
                try:
                    await router
                except asyncio.CancelledError:
                    pass


@pytest.mark.asyncio
async def test_rbc_json_data():
    """Test RBC with JSON serialized data"""
    N = 4
    f = 1
    leader = 0
    sid = "test:rbc:json"

    input_queues = [asyncio.Queue() for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]
    send_queues = [asyncio.Queue() for _ in range(N)]

    # Test with JSON data
    test_obj = {"tx": ["tx1", "tx2", "tx3"], "round": 0}
    test_data = json.dumps(test_obj).encode()

    await input_queues[leader].put(test_data)

    tasks = []
    for i in range(N):
        params = CommonParams(sid=sid, pid=i, N=N, f=f, leader=leader)
        task = asyncio.create_task(
            reliablebroadcast(params, input_queues[i], recv_queues[i], send_queues)
        )
        tasks.append(task)

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
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)

        # Verify all nodes got same JSON
        for result in results:
            assert result == test_data
            received_obj = json.loads(result.decode())
            assert received_obj == test_obj

    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass
