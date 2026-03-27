import asyncio
from dataclasses import dataclass


@dataclass
class RoundContext:
    N: int
    r: int

    # 接收网络消息的入口队列
    coin_recvs: list[asyncio.Queue]
    aba_recvs: list[asyncio.Queue]
    rbc_recvs: list[asyncio.Queue]
    tpke_recv: asyncio.Queue

    # 子协议对外广播的出口队列
    coin_bcasts: list[asyncio.Queue]
    aba_bcasts: list[asyncio.Queue]
    rbc_bcasts: list[asyncio.Queue]
    tpke_bcast: asyncio.Queue

    # 协议间的数据管道
    aba_inputs: list[asyncio.Queue]
    aba_outputs: list[asyncio.Queue]
    rbc_outputs: list[asyncio.Queue]

    # 主干协议管道
    acs_input: asyncio.Queue
    acs_output: asyncio.Queue
    hb_propose: asyncio.Queue

    @classmethod
    def create(cls, N: int, r: int) -> RoundContext:
        return cls(
            N=N,
            r=r,
            coin_recvs=[asyncio.Queue() for _ in range(N)],
            aba_recvs=[asyncio.Queue() for _ in range(N)],
            rbc_recvs=[asyncio.Queue() for _ in range(N)],
            tpke_recv=asyncio.Queue(),
            coin_bcasts=[asyncio.Queue() for _ in range(N)],
            aba_bcasts=[asyncio.Queue() for _ in range(N)],
            rbc_bcasts=[asyncio.Queue() for _ in range(N)],
            tpke_bcast=asyncio.Queue(),
            aba_inputs=[asyncio.Queue(1) for _ in range(N)],
            aba_outputs=[asyncio.Queue(1) for _ in range(N)],
            rbc_outputs=[asyncio.Queue(1) for _ in range(N)],
            acs_input=asyncio.Queue(1),
            acs_output=asyncio.Queue(1),
            hb_propose=asyncio.Queue(1),
        )
