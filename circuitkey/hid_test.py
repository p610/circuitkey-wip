import sys
from unittest.mock import MagicMock

import pytest

from circuitkey.error import CtapError
from circuitkey.schema import Error

sys.modules["usb_hid"] = MagicMock()

import circuitkey.hid as hid

MULTI_PACKET = (
    b"\x00\x00\x00\x40\x01\x00`testtesttesttesttesttesttesttesttesttesttesttesttesttestt",
    b"\x00\x00\x00\x40\x81esttesttesttesttesttesttesttesttesttest" + b"\x00" * 20,
)


@pytest.mark.asyncio
async def test_send_single_packet():
    device = MagicMock()

    await hid.send(int(128).to_bytes(4, "big"), 0x01, b"test", device=device)

    device.send_report.assert_called_once_with(
        b"\x00\x00\x00\x80\x01\x00\x04test" + b"\x00" * 53
    )


@pytest.mark.asyncio
async def test_send_multiple_packets():
    device = MagicMock()

    await hid.send(int(64).to_bytes(4, "big"), 0x01, b"test" * 24, device=device)

    assert device.send_report.call_count == 2
    device.send_report.assert_any_call(MULTI_PACKET[0])
    device.send_report.assert_any_call(MULTI_PACKET[1])


def test_receive_packet():
    device = MagicMock()
    device.get_last_received_report.side_effect = MULTI_PACKET

    data = hid.receive(device)

    assert data.cid == b"\x00\x00\x00\x40"
    assert data.cmd == 0x01
    assert data.payload == b"test" * 24


def test_receive_packet_out_of_sequence():
    device = MagicMock()
    device.get_last_received_report.side_effect = (
        MULTI_PACKET[1],
        MULTI_PACKET[0],
    )

    with pytest.raises(CtapError) as e:
        hid.receive(device)
        assert e.code == Error.INVALID_SEQ


def test_receive_packet_with_invalid_length():
    device = MagicMock()
    device.get_last_received_report.return_value = b"\x00" * 63

    with pytest.raises(CtapError) as e:
        hid.receive(device)
        assert e.code == Error.INVALID_LENGTH


def test_receive_packet_with_invalid_cid():
    device = MagicMock()
    device.get_last_received_report.side_effect = (
        MULTI_PACKET[0],
        b"\x00\x00\x00\x00" + MULTI_PACKET[1][4:],
    )

    with pytest.raises(CtapError) as e:
        hid.receive(device)
        assert e.code == Error.INVALID_CHANNEL
