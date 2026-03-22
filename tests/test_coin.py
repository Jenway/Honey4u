import asyncio

import pytest

from crypto.threshsig import dealer
from honeybadgerbft.commoncoin import CoinParams, shared_coin


@pytest.fixture
def signing_keys():
    """Generate threshold signing keys"""
    # Generate keys for N=4, f=1 (need f+1=2 shares)
    pk, sks = dealer(4, 2)
    return pk, sks


@pytest.mark.asyncio
async def test_coin_single_value(signing_keys):
    """Test that all nodes get the same coin value"""
    N = 4
    f = 1
    sid = "test:coin:single"

    pk, sks = signing_keys

    # Create broadcast and receive queues for each node
    bcast_queues = [asyncio.Queue() for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]

    # Create coin params for each node
    coin_tasks = []
    for i in range(N):
        params = CoinParams(
            sid=sid,
            pid=i,
            N=N,
            f=f,
            leader=0,  # Coin doesn't really use leader, but it's required by CommonParams
            PK=pk,
            SK=sks[i],  # Node i gets its share of the key
        )
        task = asyncio.create_task(
            shared_coin(params, bcast_queues[i], recv_queues[i], single_bit=True)
        )
        coin_tasks.append(task)

    # Message router: route broadcasts to all nodes
    async def msg_router(sender_idx: int):
        """Route messages from sender to all receivers"""
        while True:
            try:
                try:
                    message = bcast_queues[sender_idx].get_nowait()
                    # Broadcast to all receivers except self
                    for j in range(N):
                        if j != sender_idx:
                            await recv_queues[j].put((sender_idx, message))
                except asyncio.QueueEmpty:
                    await asyncio.sleep(0.001)
            except asyncio.CancelledError:
                break

    routers = [asyncio.create_task(msg_router(i)) for i in range(N)]

    try:
        # Get coin getter functions from all nodes
        coin_fns = await asyncio.wait_for(asyncio.gather(*coin_tasks), timeout=10.0)

        # Call coin(0) from each node and collect results
        coin_calls = [coin_fn(0) for coin_fn in coin_fns]
        results = await asyncio.wait_for(asyncio.gather(*coin_calls), timeout=10.0)

        # All nodes should get the same coin value (0 or 1)
        coin_value = results[0]
        assert coin_value in (0, 1), f"Coin value should be 0 or 1, got {coin_value}"

        for i in range(1, N):
            assert results[i] == coin_value, f"Node {i} got {results[i]}, expected {coin_value}"

    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass


@pytest.mark.asyncio
async def test_coin_multiple_rounds(signing_keys):
    """Test coin over multiple rounds"""
    N = 4
    f = 1
    sid = "test:coin:multround"

    pk, sks = signing_keys

    bcast_queues = [asyncio.Queue() for _ in range(N)]
    recv_queues = [asyncio.Queue() for _ in range(N)]

    coin_tasks = []
    for i in range(N):
        params = CoinParams(
            sid=sid,
            pid=i,
            N=N,
            f=f,
            leader=0,  # Coin doesn't really use leader, but it's required by CommonParams
            PK=pk,
            SK=sks[i],
        )
        task = asyncio.create_task(
            shared_coin(params, bcast_queues[i], recv_queues[i], single_bit=True)
        )
        coin_tasks.append(task)

    async def msg_router(sender_idx: int):
        while True:
            try:
                try:
                    message = bcast_queues[sender_idx].get_nowait()
                    for j in range(N):
                        if j != sender_idx:
                            await recv_queues[j].put((sender_idx, message))
                except asyncio.QueueEmpty:
                    await asyncio.sleep(0.001)
            except asyncio.CancelledError:
                break

    routers = [asyncio.create_task(msg_router(i)) for i in range(N)]

    try:
        coin_fns = await asyncio.wait_for(asyncio.gather(*coin_tasks), timeout=10.0)

        # Test multiple rounds
        num_rounds = 5
        for round_num in range(num_rounds):
            coin_calls = [coin_fn(round_num) for coin_fn in coin_fns]
            results = await asyncio.wait_for(asyncio.gather(*coin_calls), timeout=10.0)

            # All nodes should agree on coin value for this round
            coin_value = results[0]
            for i in range(1, N):
                assert results[i] == coin_value, (
                    f"Round {round_num}: Node {i} got {results[i]}, expected {coin_value}"
                )

    finally:
        for router in routers:
            router.cancel()
            try:
                await router
            except asyncio.CancelledError:
                pass
