import asyncio
import json

import pytest

from honey.crypto.merkle import encode
from honey.data.broadcast_mempool import BroadcastMempool
from honey.subprotocols.reliable_broadcast import reliablebroadcast
from honey.support.messages import RbcEcho, RbcReady, RbcVal
from honey.support.params import CommonParams


# Helper to route messages between nodes
async def msg_router(sender_idx: int, send_queues: list, recv_queues: list):
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


async def boil_plate(N: int, f: int, leader: int, sid, round_no: int):
    # Create input/output queues for each node
    input_queues = [asyncio.Queue() for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]
    send_queues = [asyncio.Queue() for _ in range(N)]

    mempool = BroadcastMempool(max_size=100, expire_rounds=5)

    test_data = b"hello world"

    # Put data in leader's input queue
    await input_queues[leader].put(test_data)

    # Create RBC params for each node
    tasks = []
    routers = []

    # Wait for RBC to complete with timeout
    try:
        async with asyncio.TaskGroup() as tg:
            for i in range(N):
                params = CommonParams(sid=sid, pid=i, N=N, f=f, leader=leader)
                tasks.append(
                    tg.create_task(
                        reliablebroadcast(
                            params,
                            input_queues[i],
                            recv_queues[i],
                            send_queues[i],
                            mempool,
                            round_no,
                        )
                    )
                )
                routers.append(tg.create_task(msg_router(i, send_queues, recv_queues)))
            payload_ids = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)

        # All nodes should get the same payload_id
        assert len(set(payload_ids)) == 1, "All nodes should have the same payload_id"

        # Verify data in mempool
        payload_id = payload_ids[0]
        broadcast_data = mempool.get(payload_id)
        assert broadcast_data is not None, "Payload should be in mempool"
        assert broadcast_data.payload == test_data, "Payload data should match"
        assert broadcast_data.round_no == round_no, "Round number should match"
        assert broadcast_data.sender_id == leader, "Sender should be leader"

    finally:
        # Clean up routers
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_rbc_single_leader():
    """Test RBC with one leader broadcasting to others"""
    N = 4
    f = 1
    leader = 0
    sid = "test:rbc:single"
    round_no = 0

    # Create input/output queues for each node
    input_queues = [asyncio.Queue() for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]
    send_queues = [asyncio.Queue() for _ in range(N)]

    # Create shared mempool for all RBC instances
    mempool = BroadcastMempool(max_size=100, expire_rounds=5)

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
                input_queues[i],
                recv_queues[i],
                send_queues[i],
                mempool,
                round_no,
            )
        )
        tasks.append(task)

    # Start message routers for each node
    routers = []
    for i in range(N):
        router = asyncio.create_task(msg_router(i, send_queues, recv_queues))
        routers.append(router)

    # Wait for RBC to complete with timeout
    try:
        payload_ids = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)

        # All nodes should get the same payload_id
        assert len(set(payload_ids)) == 1, "All nodes should have the same payload_id"

        # Verify data in mempool
        payload_id = payload_ids[0]
        broadcast_data = mempool.get(payload_id)
        assert broadcast_data is not None, "Payload should be in mempool"
        assert broadcast_data.payload == test_data, "Payload data should match"
        assert broadcast_data.round_no == round_no, "Round number should match"
        assert broadcast_data.sender_id == leader, "Sender should be leader"

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
        round_no = 0

        # Create queues
        input_queues = [asyncio.Queue() for _ in range(N)]
        recv_queues = [asyncio.Queue() for _ in range(N)]
        send_queues = [asyncio.Queue() for _ in range(N)]

        # Create shared mempool
        mempool = BroadcastMempool(max_size=100, expire_rounds=5)

        test_data = f"data_from_leader_{leader}".encode()
        await input_queues[leader].put(test_data)

        # Create RBC tasks
        tasks = []
        for i in range(N):
            params = CommonParams(sid=sid, pid=i, N=N, f=f, leader=leader)
            task = asyncio.create_task(
                reliablebroadcast(
                    params, input_queues[i], recv_queues[i], send_queues[i], mempool, round_no
                )
            )
            tasks.append(task)

        routers = []
        for i in range(N):
            router = asyncio.create_task(msg_router(i, send_queues, recv_queues))
            routers.append(router)

        try:
            payload_ids = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)

            # All nodes should get same payload_id from leader
            assert len(set(payload_ids)) == 1, "All nodes should have the same payload_id"

            # Verify data in mempool
            payload_id = payload_ids[0]
            broadcast_data = mempool.get(payload_id)
            assert broadcast_data is not None, "Payload should be in mempool"
            assert broadcast_data.payload == test_data, "Payload data should match"

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
    round_no = 0

    input_queues = [asyncio.Queue() for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]
    send_queues = [asyncio.Queue() for _ in range(N)]

    # Create shared mempool
    mempool = BroadcastMempool(max_size=100, expire_rounds=5)

    # Test with JSON data
    test_obj = {"tx": ["tx1", "tx2", "tx3"], "round": 0}
    test_data = json.dumps(test_obj).encode()

    await input_queues[leader].put(test_data)

    tasks = []
    for i in range(N):
        params = CommonParams(sid=sid, pid=i, N=N, f=f, leader=leader)
        task = asyncio.create_task(
            reliablebroadcast(
                params, input_queues[i], recv_queues[i], send_queues[i], mempool, round_no
            )
        )
        tasks.append(task)

    routers = [asyncio.create_task(msg_router(i, send_queues, recv_queues)) for i in range(N)]

    try:
        payload_ids = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)

        # Verify all nodes got same payload_id
        assert len(set(payload_ids)) == 1, "All nodes should have the same payload_id"

        # Verify data in mempool
        payload_id = payload_ids[0]
        broadcast_data = mempool.get(payload_id)
        assert broadcast_data is not None, "Payload should be in mempool"
        assert broadcast_data.payload == test_data, "Payload data should match"

        received_obj = json.loads(broadcast_data.payload.decode())
        assert received_obj == test_obj, "JSON object should match"

    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_rbc_rejects_invalid_echo_index():
    N = 4
    f = 1
    leader = 0
    pid = 1
    sid = "test:rbc:invalid-echo"
    round_no = 0
    payload = b"invalid echo should not count"

    roothash, shards, proofs = encode(payload, N - 2 * f, N)

    input_queue = asyncio.Queue()
    recv_queue = asyncio.Queue()
    send_queue = asyncio.Queue()
    mempool = BroadcastMempool(max_size=100, expire_rounds=5)
    params = CommonParams(sid=sid, pid=pid, N=N, f=f, leader=leader)

    task = asyncio.create_task(
        reliablebroadcast(params, input_queue, recv_queue, send_queue, mempool, round_no)
    )

    await recv_queue.put(
        (
            leader,
            RbcVal(
                roothash=roothash,
                proof=proofs[pid].to_bytes(),
                stripe=shards[pid],
                stripe_index=pid,
            ),
        )
    )

    await recv_queue.put(
        (
            2,
            RbcEcho(
                roothash=roothash,
                proof=proofs[2].to_bytes(),
                stripe=shards[2],
                stripe_index=pid,
            ),
        )
    )
    for sender in range(3):
        await recv_queue.put((sender, RbcReady(roothash=roothash)))

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(task), timeout=0.1)

    await recv_queue.put(
        (
            2,
            RbcEcho(
                roothash=roothash,
                proof=proofs[2].to_bytes(),
                stripe=shards[2],
                stripe_index=2,
            ),
        )
    )
    await recv_queue.put(
        (
            3,
            RbcEcho(
                roothash=roothash,
                proof=proofs[3].to_bytes(),
                stripe=shards[3],
                stripe_index=3,
            ),
        )
    )

    payload_id = await asyncio.wait_for(task, timeout=5.0)
    assert mempool.get(payload_id) is not None
