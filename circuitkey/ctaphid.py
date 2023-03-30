import asyncio
from typing import Awaitable

from adafruit_logging import getLogger

from circuitkey import cbor, channel, hid, info, ui, util
from circuitkey.error import CtapError
from circuitkey.schema import (CTAPHID_BROADCAST_CID, CtaphidCmd, Error,
                               KeepaliveStatusCode)

log = getLogger(__name__)


async def cbor_cmd(cid: bytes, payload: bytes):
    """
    CTAPHID_CBOR (0x10)

    Request
    CMD 	    CTAPHID_CBOR
    BCNT 	    1..(n + 1)
    DATA 	    CTAP command byte
    DATA + 1 	n bytes of CBOR encoded data

    Response at success
    CMD 	    CTAPHID_CBOR
    BCNT 	    1..(n + 1)
    DATA 	    CTAP status code
    DATA + 1 	n bytes of CBOR encoded data
    """
    log.info("Processing cbor command")

    response = await cbor.process(payload)
    await hid.send(cid, 0x10, response)


async def init_cmd(cid: bytes, payload: bytes):
    """
    CTAPHID_INIT (0x06)

    Request
    CMD 	CTAPHID_INIT
    BCNT 	8
    DATA 	8-byte nonce

    Response at success
    CMD 	    CTAPHID_INIT
    BCNT 	    17 (see note below)
    DATA 	    8-byte nonce
    DATA+8 	    4-byte channel ID
    DATA+12 	CTAPHID protocol version identifier
    DATA+13 	Major device version number
    DATA+14 	Minor device version number
    DATA+15 	Build device version number
    DATA+16 	Capabilities flags
    """
    if cid == CTAPHID_BROADCAST_CID:
        assigned_cid = channel.generate_cid()
    else:
        assigned_cid = cid

    nonce = payload

    assert len(nonce) == 8, "Nonce must be 8 bytes long"

    protocol_version, device_version, capabilities_flag = info.CTAP_INFO

    buffer = (
        nonce,
        assigned_cid,
        protocol_version,
        device_version,
        capabilities_flag,
    )

    buffer = b"".join(buffer)

    log.info("New channel created: %s", util.hexlify(cid))
    await hid.send(cid, CtaphidCmd.INIT, buffer)


async def ping_cmd(cid: bytes, payload: bytes):
    """
    CTAPHID_PING (0x01)

    Request
    CMD 	CTAPHID_PING
    BCNT 	0..n
    DATA 	n bytes

    Response at success
    CMD 	CTAPHID_PING
    BCNT 	n
    DATA 	N bytes
    """
    log.info("Ping command received, pinging back...")
    await hid.send(cid, CtaphidCmd.PING, payload)


async def cancel_cmd(cid: bytes, payload: bytes):
    """
    CTAPHID_CANCEL (0x11)

    Request
    CMD 	CTAPHID_CANCEL
    BCNT 	0
    DATA 	none
    """
    global cbor_active_tasks
    log.info("Client requested cancelation, sending confirmation")

    if len(cbor_active_tasks) > 0:
        log.info("Checking for active tasks")
        cancelled_task_counter = 0

        async def cancel(task: asyncio.Task):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                log.debug("Task cancelled")

            cbor_active_tasks.remove((cid, task))

        for task_cid, task in cbor_active_tasks:
            if cid == task_cid:
                if not task.done():
                    await cancel(task)
                    cancelled_task_counter += 1
                else:
                    log.debug("CBOR task with CID[%s] already done", task_cid)

        log.info("Cancelled %d tasks", cancelled_task_counter)
    else:
        log.info("No active CBOR tasks found. Cancelation not needed")


async def error_cmd(cid: bytes, error_code: Error):
    """
    CTAPHID_ERROR (0x3F)

    This command code is used in response messages only.
    CMD 	CTAPHID_ERROR
    BCNT 	1
    DATA 	Error code
    """
    log.info("Sending ctap error code - %d", error_code)
    assert error_code in Error, "Invalid error code"
    await hid.send(cid, CtaphidCmd.ERROR, error_code.to_byte())


async def keepalive_cmd(cid: bytes, status_code: KeepaliveStatusCode):
    """
    CTAPHID_KEEPALIVE (0x3B)

    Request:
    CMD 	CTAPHID_KEEPALIVE
    BCNT 	1
    DATA 	Status code

    Note:
    The authenticator MAY send a keepalive response at any time, even if the
    client has not sent a keepalive request. The client MUST NOT send a
    keepalive request if it has not received a keepalive response from the
    authenticator.

    This command code is sent while processing a CTAPHID_MSG, CTAPHID_CBOR.
    It should be sent at least every 100ms and whenever the status changes.
    """
    log.info("Sending keepalive %d", status_code)
    await hid.send(cid, CtaphidCmd.KEEPALIVE, status_code.to_byte())


async def wink_cmd(cid: bytes, payload: bytes):
    """
    CTAPHID_WINK (0x08)

    Request
    CMD 	CTAPHID_WINK
    BCNT 	0
    DATA 	N/A

    Response at success
    CMD 	CTAPHID_WINK
    BCNT 	0
    DATA 	N/A
    """
    log.info("Wink command received, winking...")
    await hid.send(cid, CtaphidCmd.WINK, bytes())
    await ui.get_ui().wink()


async def keepalive_task(milliseconds: int):
    while True:
        try:
            await keepalive_cmd(CTAPHID_BROADCAST_CID, KeepaliveStatusCode.PROCESSING)
            await asyncio.sleep(milliseconds / 1000)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.error("Unexpected error (that is ignored) in keepalive task: %s", e)


cbor_active_tasks = []


async def process(cid: bytes, cmd: int, payload: bytes):
    CTAPHID_COMMANDS = [
        # Mandatory commands
        (CtaphidCmd.PING, ping_cmd),
        (CtaphidCmd.INIT, init_cmd),
        (CtaphidCmd.CBOR, cbor_cmd),
        (CtaphidCmd.CANCEL, cancel_cmd),
        # Optional commands
        (CtaphidCmd.WINK, wink_cmd),
    ]

    async def error_handler(func: Awaitable[any]):
        try:
            await func
        except CtapError as e:
            log.error(
                "CtapError occured while processing command %d: %s. Responding with error code.",
                cmd,
                e,
            )
            await error_cmd(cid, e.code)

    for cmd_code, handler in CTAPHID_COMMANDS:
        if cmd_code == cmd:
            try:
                h_task = asyncio.create_task(
                    error_handler(handler(cid, payload)), name="CtapHandlerTask"
                )

                if cmd == CtaphidCmd.CBOR:
                    log.info(
                        "CBOR command received, starting background keepalive task"
                    )
                    ka_task = asyncio.create_task(
                        keepalive_task(50), name="KeepaliveTask"
                    )
                    cbor_active_tasks.append((cid, ka_task))

                    await util.wait_until_first_complete(ka_task, h_task)
                else:
                    await h_task
            except CtapError as e:
                log.error("CtapError occured while processing command %d: %s", cmd, e)
                await error_cmd(cid, e.code)

            return

    # if we reach this point, the command is not supported
    await error_cmd(cid, Error.INVALID_COMMAND)
