import asyncio
import random
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_mock

from circuitkey.schema import (CTAPHID_BROADCAST_CID, CtaphidCmd, Error,
                               KeepaliveStatusCode)

sys.modules["usb_hid"] = MagicMock()

import circuitkey.ctaphid as ctaphid


@pytest.mark.asyncio
async def test_err_cmd(mocker: pytest_mock.MockFixture):
    hid_send = mocker.patch("circuitkey.hid.send")

    await ctaphid.error_cmd(b"01", Error.INVALID_COMMAND)

    hid_send.assert_called_once_with(b"01", 0x3F, b"\x01")


@pytest.mark.asyncio
async def test_ctap_ping(mocker: pytest_mock.MockFixture):
    hid_send = mocker.patch("circuitkey.hid.send")

    await ctaphid.ping_cmd(b"01", b"ping")

    hid_send.assert_called_once_with(b"01", 0x01, b"ping")


@pytest.mark.asyncio
async def test_cancel_cmd_when_no_cbor_tasks_active(mocker: pytest_mock.MockFixture):
    hid_send = mocker.patch("circuitkey.hid.send")

    cid = random.randbytes(4)

    await ctaphid.cancel_cmd(cid, b"")

    hid_send.assert_not_called()


@pytest.mark.asyncio
async def test_cancel_cmd_when_cbor_tasks_active(mocker: pytest_mock.MockFixture):
    mocker.patch("circuitkey.hid.send")

    cid = random.randbytes(4)

    async def cbor_command():
        for _ in range(5):
            asyncio.sleep(1)

    cbor_task = asyncio.create_task(cbor_command())

    ctaphid.cbor_active_tasks.append((cid, cbor_task))

    await ctaphid.cancel_cmd(cid, b"")

    assert cbor_task.cancelled()


@pytest.mark.asyncio
async def test_wink_cmd(mocker: pytest_mock.MockFixture):
    UI = MagicMock()
    UI.wink = AsyncMock()

    mocker.patch("circuitkey.ui.get_ui", return_value=UI)

    hid_send = mocker.patch("circuitkey.hid.send")

    await ctaphid.wink_cmd(b"01", bytes())

    UI.wink.assert_called_once()
    hid_send.assert_called_once_with(b"01", 0x08, b"")


@pytest.mark.asyncio
async def test_keepalive_cmd(mocker: pytest_mock.MockFixture):
    hid_send = mocker.patch("circuitkey.hid.send")

    await ctaphid.keepalive_cmd(b"01", KeepaliveStatusCode.PROCESSING)

    hid_send.assert_called_once_with(b"01", 0x3B, b"\x01")


@pytest.mark.asyncio
async def test_init_cmd(mocker: pytest_mock.MockFixture):
    hid_send = mocker.patch("circuitkey.hid.send")
    nonce = random.randbytes(8)

    await ctaphid.init_cmd(CTAPHID_BROADCAST_CID, nonce)

    hds_args = hid_send.call_args_list[0][0]

    assert hds_args[0] == CTAPHID_BROADCAST_CID
    assert hds_args[1] == CtaphidCmd.INIT

    assert len(hds_args[2]) == 17
    assert hds_args[2][0:8] == nonce
    assert (
        hds_args[2][8:12] != CTAPHID_BROADCAST_CID
    ), "Newly generated CID should not be broadcast CID"
    assert hds_args[2][12] == 2, "Protocol version should  be 2"
    assert hds_args[2][13:16] == bytes((0, 1, 0)), "Version should be 0.1.0"
    assert hds_args[2][16] == 5, "Wink(1) + Cbor(4)"


@pytest.mark.asyncio
async def test_cbor_cmd(mocker: pytest_mock.MockFixture):
    hid_send = mocker.patch("circuitkey.hid.send")
    mocker.patch("circuitkey.cbor.process", return_value=b"")
    cbor_payload = random.randbytes(8)
    cid = random.randbytes(4)

    await ctaphid.cbor_cmd(cid, cbor_payload)

    hid_send.assert_called_once_with(cid, 0x10, b"")


@pytest.mark.asyncio
async def test_process_non_cbor_cmd(mocker: pytest_mock.MockFixture):
    ping_cmd = mocker.patch("circuitkey.ctaphid.ping_cmd", return_value=AsyncMock())
    keep_alive_task = mocker.patch("circuitkey.ctaphid.keepalive_task")

    cid = random.randbytes(4)
    cmd = CtaphidCmd.PING
    payload = random.randbytes(8)

    await ctaphid.process(cid, cmd, payload)

    keep_alive_task.assert_not_called()
    ping_cmd.assert_called_once_with(cid, payload)


@pytest.mark.asyncio
async def test_process_cbor_cmd(mocker: pytest_mock.MockFixture):
    cbor_cmd = mocker.patch("circuitkey.ctaphid.cbor_cmd", return_value=AsyncMock())
    keep_alive_task = mocker.patch("circuitkey.ctaphid.keepalive_task")

    cid = random.randbytes(4)
    cmd = CtaphidCmd.CBOR
    payload = random.randbytes(8)

    await ctaphid.process(cid, cmd, payload)

    keep_alive_task.assert_called_once_with(50)
    cbor_cmd.assert_called_once_with(cid, payload)

    assert keep_alive_task.cancelled()
