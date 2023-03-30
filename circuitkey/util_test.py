import asyncio

import pytest

from circuitkey.util import wait_until_first_complete


async def task1(sleep):
    await asyncio.sleep(sleep)


async def task2(sleep):
    await asyncio.sleep(sleep)


@pytest.mark.asyncio
async def test_wait_until_first_complete():
    t1 = asyncio.create_task(task1(10))
    t2 = asyncio.create_task(task2(0))

    done, pending = await wait_until_first_complete(t1, t2)

    assert len(done) == 1
    assert len(pending) == 1

    assert done[0] == t2
    assert pending[0] == t1

    try:
        await t1
        assert t1.cancelled()
    except asyncio.CancelledError:
        pass
