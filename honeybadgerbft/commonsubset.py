import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from honeybadgerbft.params import CommonParams

logger = logging.getLogger(__name__)


@dataclass
class CSParams(CommonParams):
    """Parameters for asynchronous common subset with validation"""

    pass  # All common params already inherited


async def commonsubset(
    params: CSParams,
    rbc_queues: list[asyncio.Queue],
    aba_input_queues: list[asyncio.Queue],
    aba_output_queues: list[asyncio.Queue],
) -> tuple[Any | None, ...]:
    """The BKR93 algorithm for asynchronous common subset.

    :param CSParams params: validated parameters (pid, N, f)
    :param List[asyncio.Queue] rbc_queues: array of N input queues
        containing reliable broadcast outputs
    :param List[asyncio.Queue] aba_input_queues: array of N output queues
        for binary agreement inputs
    :param List[asyncio.Queue] aba_output_queues: array of N input queues
        containing binary agreement outputs
    :return: an N-element tuple, each element either ``None`` or a value
    """
    N = params.N
    f = params.f
    # pid = params.pid

    assert len(rbc_queues) == N
    assert len(aba_input_queues) == N
    assert len(aba_output_queues) == N

    aba_inputted = [False] * N
    aba_values = [0] * N
    rbc_values: list[Any | None] = [None] * N

    def _put_aba_input_once(j: int, value: int) -> None:
        if aba_inputted[j]:
            return
        aba_inputted[j] = True
        try:
            aba_input_queues[j].put_nowait(value)
        except asyncio.QueueFull:
            # Another path may already have filled this single-slot queue.
            pass

    async def _recv_rbc(j: int) -> None:
        """Receive output from reliable broadcast"""
        rbc_values[j] = await rbc_queues[j].get()
        # Provide 1 as input to the corresponding bin agreement
        _put_aba_input_once(j, 1)

    async def _recv_aba(j: int) -> None:
        """Receive output from binary agreement"""
        aba_values[j] = await aba_output_queues[j].get()

        if sum(aba_values) >= N - f:
            # Provide 0 to all other aba
            for k in range(N):
                _put_aba_input_once(k, 0)

    # Start all ABA receive tasks
    aba_tasks = [asyncio.create_task(_recv_aba(j)) for j in range(N)]

    # Start all RBC receive tasks
    rbc_tasks = [asyncio.create_task(_recv_rbc(j)) for j in range(N)]

    # Wait for all binary agreements to complete
    await asyncio.gather(*aba_tasks)

    assert sum(aba_values) >= N - f  # Must have at least N-f committed

    # Wait for the corresponding broadcasts (if needed) or cancel them
    for j in range(N):
        if aba_values[j]:
            # Wait for this RBC to complete
            try:
                await asyncio.wait_for(rbc_tasks[j], timeout=None)
            except asyncio.CancelledError:
                pass
            assert rbc_values[j] is not None
        else:
            # Cancel this RBC task
            rbc_tasks[j].cancel()
            rbc_values[j] = None

    return tuple(rbc_values)
