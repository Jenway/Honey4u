"""Integration tests for Binary Agreement protocol using real SharedCoin"""

import asyncio

import pytest

from honeybadgerbft.binaryagreement import BAParams, binaryagreement
from honeybadgerbft.commoncoin import CoinParams, SharedCoin


@pytest.fixture
def ba_network(signing_keys):
    """
    Creates a completely wired BA network with real SharedCoin instances.
    Returns a factory function so tests can inject TaskGroup and inputs.
    """

    def _make(tg: asyncio.TaskGroup, inputs: list[int], N=4, f=1, sid="test_ba"):
        # 依赖于 conftest.py (或本模块) 提供的真实门限签名密钥 fixture
        pk, sks = signing_keys

        # 1. BA 协议专属队列
        input_qs = [asyncio.Queue(1) for _ in range(N)]
        decide_qs = [asyncio.Queue(1) for _ in range(N)]
        ba_recv_qs = [asyncio.Queue() for _ in range(N)]
        ba_send_qs = [asyncio.Queue() for _ in range(N)]

        # 2. Coin 协议专属队列
        coin_recv_qs = [asyncio.Queue() for _ in range(N)]
        coin_send_qs = [asyncio.Queue() for _ in range(N)]

        # 注入初始值
        for i, val in enumerate(inputs):
            input_qs[i].put_nowait(val)

        # 初始化真实的 SharedCoin
        coins = [
            SharedCoin(CoinParams(sid=sid, pid=i, N=N, f=f, leader=0, PK=pk, SK=sks[i]))
            for i in range(N)
        ]

        # --- 路由器设计 ---

        # BA 路由器: 处理点对点(P2P)的消息分发
        async def ba_router(sender_id):
            try:
                while True:
                    # BA 协议内部发送的格式是 (recipient, msg)
                    recipient, msg = await ba_send_qs[sender_id].get()
                    await ba_recv_qs[recipient].put((sender_id, msg))
            except asyncio.CancelledError:
                pass

        # Coin 路由器: 处理硬币消息的全网广播(Broadcast)
        async def coin_router(sender_id):
            try:
                while True:
                    # Coin 协议发送的直接是 msg 载荷，需要广播给所有人
                    msg = await coin_send_qs[sender_id].get()
                    for recipient in range(N):
                        await coin_recv_qs[recipient].put((sender_id, msg))
            except asyncio.CancelledError:
                pass

        # 在 TaskGroup 中注册并启动所有的后台任务
        routers = []
        for i in range(N):
            # 启动真实的硬币接收监听循环
            coins[i].start(tg, coin_recv_qs[i])
            # 启动双路路由
            routers.append(tg.create_task(ba_router(i)))
            routers.append(tg.create_task(coin_router(i)))

        # 启动核心 BA 任务
        ba_tasks = []
        for i in range(N):
            params = BAParams(sid=sid, pid=i, N=N, f=f, leader=0)
            task = tg.create_task(
                binaryagreement(
                    params,
                    coins[i],
                    coin_send_qs[i],
                    input_qs[i],
                    decide_qs[i],
                    ba_recv_qs[i],
                    ba_send_qs[i],
                )
            )
            ba_tasks.append(task)

        return N, decide_qs, coins, routers, ba_tasks

    return _make


@pytest.mark.asyncio
async def test_ba_agree_on_zero(ba_network):
    """Test Binary Agreement when all nodes input 0"""
    async with asyncio.TaskGroup() as tg:
        N, decide_qs, coins, routers, ba_tasks = ba_network(
            tg, inputs=[0, 0, 0, 0], sid="test_ba_zero"
        )

        try:
            # 真实加密算法会有开销，给10秒的超时足以满足多次轮次的运算
            results = await asyncio.wait_for(
                asyncio.gather(*(dq.get() for dq in decide_qs)), timeout=10.0
            )
            assert all(r == 0 for r in results), f"Nodes disagreed or decided wrong: {results}"
        finally:
            # 极其关键：退出前取消所有无限循环的任务，防止 TaskGroup 卡死
            for r in routers:
                r.cancel()
            for c in coins:
                c.stop()
            for t in ba_tasks:
                t.cancel()


@pytest.mark.asyncio
async def test_ba_agree_on_one(ba_network):
    """Test Binary Agreement when all nodes input 1"""
    async with asyncio.TaskGroup() as tg:
        N, decide_qs, coins, routers, ba_tasks = ba_network(
            tg, inputs=[1, 1, 1, 1], sid="test_ba_one"
        )

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*(dq.get() for dq in decide_qs)), timeout=10.0
            )
            assert all(r == 1 for r in results), f"Nodes disagreed or decided wrong: {results}"
        finally:
            for r in routers:
                r.cancel()
            for c in coins:
                c.stop()
            for t in ba_tasks:
                t.cancel()


@pytest.mark.asyncio
async def test_ba_mixed_input(ba_network):
    """Test Binary Agreement with mixed input (some 0s, some 1s)"""
    async with asyncio.TaskGroup() as tg:
        # 3个0, 1个1。在 N=4, f=1 环境下由于有 2f+1=3 个相同的初始值，
        # 会在内部强行达成一致，无论硬币投出什么。
        N, decide_qs, coins, routers, ba_tasks = ba_network(
            tg, inputs=[0, 0, 0, 1], sid="test_ba_mixed"
        )

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*(dq.get() for dq in decide_qs)), timeout=10.0
            )
            # 由于输入了不同的值，我们只要确保网络中的诚实节点**达成了一致的结果**即可
            assert len(set(results)) == 1, f"Nodes disagreed: {results}"
            assert results[0] in (0, 1), f"Unexpected value decided: {results[0]}"
        finally:
            for r in routers:
                r.cancel()
            for c in coins:
                c.stop()
            for t in ba_tasks:
                t.cancel()
