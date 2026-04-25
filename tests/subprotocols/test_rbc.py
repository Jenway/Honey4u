import asyncio
import json

import pytest
from honey_acs.crypto.native import NativeMerkleRuntime
from honey_acs.messages import RbcEcho, RbcReady, RbcVal
from honey_acs.subprotocols.reliable_broadcast import BroadcastParams, RbcOutput, reliablebroadcast

MERKLE = NativeMerkleRuntime()


def _rbc_params(sid: str, pid: int, num_nodes: int, faulty: int, leader: int) -> BroadcastParams:
    return BroadcastParams(sid=sid, pid=pid, N=num_nodes, f=faulty, leader=leader, merkle=MERKLE)


async def msg_router(sender_idx: int, send_queues: list, recv_queues: list):
    """Route messages from sender to all receivers."""
    while True:
        try:
            try:
                recipient, message = send_queues[sender_idx].get_nowait()
                await recv_queues[recipient].put((sender_idx, message))
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.001)
        except asyncio.CancelledError:
            break


def _assert_consistent_outputs(
    outputs: list[RbcOutput],
    *,
    expected_payload: bytes,
    leader: int,
    num_nodes: int,
) -> None:
    assert outputs, "expected at least one RBC output"
    first = outputs[0]
    assert first.payload == expected_payload
    assert first.leader == leader
    assert len(first.shards) == num_nodes
    assert len(first.proofs) == num_nodes
    for output in outputs[1:]:
        assert output.payload == expected_payload
        assert output.roothash == first.roothash
        assert output.leader == leader
        assert len(output.shards) == num_nodes
        assert len(output.proofs) == num_nodes


@pytest.mark.asyncio
async def test_rbc_single_leader():
    """Test RBC with one leader broadcasting to others."""
    num_nodes = 4
    faulty = 1
    leader = 0
    sid = "test:rbc:single"

    input_queues = [asyncio.Queue() for _ in range(num_nodes)]
    recv_queues = [asyncio.Queue() for _ in range(num_nodes)]
    send_queues = [asyncio.Queue() for _ in range(num_nodes)]

    test_data = b"hello world"
    await input_queues[leader].put(test_data)

    tasks = []
    for pid in range(num_nodes):
        params = _rbc_params(sid, pid, num_nodes, faulty, leader)
        tasks.append(
            asyncio.create_task(
                reliablebroadcast(params, input_queues[pid], recv_queues[pid], send_queues[pid])
            )
        )

    routers = [
        asyncio.create_task(msg_router(pid, send_queues, recv_queues)) for pid in range(num_nodes)
    ]

    try:
        outputs = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
        _assert_consistent_outputs(
            outputs,
            expected_payload=test_data,
            leader=leader,
            num_nodes=num_nodes,
        )
    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_rbc_different_leaders():
    """Test RBC where each node can be leader."""
    num_nodes = 4
    faulty = 1

    for leader in range(num_nodes):
        sid = f"test:rbc:leader{leader}"
        input_queues = [asyncio.Queue() for _ in range(num_nodes)]
        recv_queues = [asyncio.Queue() for _ in range(num_nodes)]
        send_queues = [asyncio.Queue() for _ in range(num_nodes)]

        test_data = f"data_from_leader_{leader}".encode()
        await input_queues[leader].put(test_data)

        tasks = []
        for pid in range(num_nodes):
            params = _rbc_params(sid, pid, num_nodes, faulty, leader)
            tasks.append(
                asyncio.create_task(
                    reliablebroadcast(
                        params,
                        input_queues[pid],
                        recv_queues[pid],
                        send_queues[pid],
                    )
                )
            )

        routers = [
            asyncio.create_task(msg_router(pid, send_queues, recv_queues))
            for pid in range(num_nodes)
        ]

        try:
            outputs = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
            _assert_consistent_outputs(
                outputs,
                expected_payload=test_data,
                leader=leader,
                num_nodes=num_nodes,
            )
        finally:
            for router in routers:
                router.cancel()
                try:
                    await router
                except asyncio.CancelledError:
                    pass


@pytest.mark.asyncio
async def test_rbc_json_data():
    """Test RBC with JSON serialized data."""
    num_nodes = 4
    faulty = 1
    leader = 0
    sid = "test:rbc:json"

    input_queues = [asyncio.Queue() for _ in range(num_nodes)]
    recv_queues = [asyncio.Queue() for _ in range(num_nodes)]
    send_queues = [asyncio.Queue() for _ in range(num_nodes)]

    test_obj = {"tx": ["tx1", "tx2", "tx3"], "round": 0}
    test_data = json.dumps(test_obj).encode()
    await input_queues[leader].put(test_data)

    tasks = []
    for pid in range(num_nodes):
        params = _rbc_params(sid, pid, num_nodes, faulty, leader)
        tasks.append(
            asyncio.create_task(
                reliablebroadcast(params, input_queues[pid], recv_queues[pid], send_queues[pid])
            )
        )

    routers = [
        asyncio.create_task(msg_router(pid, send_queues, recv_queues)) for pid in range(num_nodes)
    ]

    try:
        outputs = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
        _assert_consistent_outputs(
            outputs,
            expected_payload=test_data,
            leader=leader,
            num_nodes=num_nodes,
        )
        received_obj = json.loads(outputs[0].payload.decode())
        assert received_obj == test_obj
    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_rbc_rejects_invalid_echo_index():
    num_nodes = 4
    faulty = 1
    leader = 0
    pid = 1
    sid = "test:rbc:invalid-echo"
    payload = b"invalid echo should not count"

    roothash, shards, proofs = MERKLE.encode(payload, num_nodes - 2 * faulty, num_nodes)

    input_queue = asyncio.Queue()
    recv_queue = asyncio.Queue()
    send_queue = asyncio.Queue()
    params = _rbc_params(sid, pid, num_nodes, faulty, leader)

    task = asyncio.create_task(reliablebroadcast(params, input_queue, recv_queue, send_queue))

    await recv_queue.put(
        (
            leader,
            RbcVal(
                roothash=roothash,
                proof=proofs[pid],
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
                proof=proofs[2],
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
                proof=proofs[2],
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
                proof=proofs[3],
                stripe=shards[3],
                stripe_index=3,
            ),
        )
    )

    output = await asyncio.wait_for(task, timeout=5.0)
    assert output.payload == payload
    assert output.roothash == roothash
    assert output.leader == leader
