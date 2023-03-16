import asyncio
import inspect
import typing


async def wait_until_first_complete(*aws: asyncio.Task, timeout=None) -> tuple:
    # This is a hack because at the moment (version 0.5.19) CircuitPython
    # version of asyncio does not support asyncio.wait

    assert len(aws) > 0, "At least one task must be provided"
    assert all(
        isinstance(t, asyncio.Task) for t in aws
    ), "All tasks must be asyncio.Task"

    async def gather(*ts):
        def cancel():
            for t in ts:
                if not t.cancelled() and not t.done():
                    t.cancel()

        try:
            while True:
                for i in range(len(ts)):
                    if ts[i].done():
                        cancel()
                        return
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            cancel()

    await asyncio.wait_for(gather(*aws), timeout=timeout)

    done = []
    pending = []

    for t in aws:
        if t.done():
            done.append(t)
        else:
            pending.append(t)

    return (done, pending)


def next_tick(func: typing.Callable) -> typing.Callable:
    async def wrapper(*args, **kwargs):
        if inspect.iscoroutinefunction(func):
            result = await func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)
        await asyncio.sleep(0)
        return result

    return wrapper


def hexlify(data: bytes) -> str:
    return "".join("{:02x}".format(b) for b in data)
