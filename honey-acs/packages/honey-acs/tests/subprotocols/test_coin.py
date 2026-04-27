import asyncio

import pytest
from honey_acs.messages import CoinShareMessage
from honey_acs.subprotocols.common_coin import CoinParams, SharedCoin


@pytest.fixture
def coin_network(signing_keys):
    """N=4 事件驱动路由模拟网络"""

    async def _make(tg: asyncio.TaskGroup, sid: str):
        runtimes = signing_keys
        N, f = 4, 1

        send_queues = [asyncio.Queue() for _ in range(N)]
        recv_queues = [asyncio.Queue() for _ in range(N)]

        # 如果原版 CommonParams 要求 leader 参数，请在这里保留 leader=0
        coins = [
            SharedCoin(CoinParams(sid=sid, pid=i, N=N, f=f, leader=0, crypto=runtimes[i]))
            for i in range(N)
        ]

        async def node_router(sender_id: int):
            try:
                while True:
                    payload = await send_queues[sender_id].get()
                    for receiver_id in range(N):
                        await recv_queues[receiver_id].put((sender_id, payload))
            except asyncio.CancelledError:
                pass

        router_tasks = [tg.create_task(node_router(i)) for i in range(N)]

        for i in range(N):
            coins[i].start(tg, recv_queues[i])

        return coins, send_queues, router_tasks

    return _make


@pytest.mark.asyncio
async def test_coin_is_consistent_across_rounds(coin_network):
    async with asyncio.TaskGroup() as tg:
        coins, send_queues, router_tasks = await coin_network(tg, "test:multi")

        try:
            for round_id in range(5):
                results = await asyncio.gather(
                    *(coins[i].get_coin(round_id, send_queues[i]) for i in range(len(coins)))
                )

                assert len(set(results)) == 1, f"Round {round_id}: Nodes disagreed {results}"

                for c in coins:
                    c.purge_round(round_id)
        finally:
            for task in router_tasks:
                task.cancel()
            for c in coins:
                c.stop()


@pytest.mark.asyncio
async def test_coin_skips_late_and_duplicate_shares_after_decision() -> None:
    class FakeCoinRuntime:
        players = 4
        threshold = 2

        def __init__(self) -> None:
            self.verify_calls = 0

        def sign_share(self, msg: bytes) -> bytes:
            del msg
            return b"self-share"

        def verify_share(self, player_id: int, share: bytes, msg: bytes) -> bool:
            del player_id, share, msg
            self.verify_calls += 1
            return True

        def combine_trusted_shares(self, shares: dict[int, bytes], msg: bytes) -> bytes:
            del shares, msg
            return b"combined"

        def verify_combined(self, signature: bytes, msg: bytes) -> bool:
            del signature, msg
            return True

    crypto = FakeCoinRuntime()
    coin = SharedCoin(CoinParams(sid="test:late", pid=0, N=4, f=1, leader=0, crypto=crypto))
    receive_queue: asyncio.Queue[tuple[int, object]] = asyncio.Queue()
    broadcast_queue: asyncio.Queue[CoinShareMessage] = asyncio.Queue()

    async with asyncio.TaskGroup() as tg:
        coin.start(tg, receive_queue)

        decision_task = asyncio.create_task(coin.get_coin(0, broadcast_queue))
        await broadcast_queue.get()

        await receive_queue.put((1, CoinShareMessage(round_id=0, signature=b"share-1")))
        await asyncio.wait_for(decision_task, timeout=1.0)

        assert crypto.verify_calls == 1

        await receive_queue.put((1, CoinShareMessage(round_id=0, signature=b"share-1-dup")))
        await receive_queue.put((2, CoinShareMessage(round_id=0, signature=b"share-2-late")))
        await asyncio.sleep(0)

        assert crypto.verify_calls == 1
        coin.stop()
