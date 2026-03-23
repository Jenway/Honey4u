import asyncio

import pytest

from honeybadgerbft.commoncoin import CoinParams, SharedCoin


@pytest.fixture
def coin_network(signing_keys):
    """N=4 事件驱动路由模拟网络"""

    async def _make(tg: asyncio.TaskGroup, sid: str):
        pk, sks = signing_keys
        N, f = 4, 1

        send_queues = [asyncio.Queue() for _ in range(N)]
        recv_queues = [asyncio.Queue() for _ in range(N)]

        # 如果原版 CommonParams 要求 leader 参数，请在这里保留 leader=0
        coins = [
            SharedCoin(CoinParams(sid=sid, pid=i, N=N, f=f, leader=0, PK=pk, SK=sks[i]))
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
