import asyncio
from typing import Optional, Tuple

import usb_hid
from adafruit_logging import getLogger

from circuitkey.error import AbortError, CtapError
from circuitkey.schema import CtapCommand, CtaphidCmd, Error

log = getLogger(__name__)

# HID report descriptor for U2F devices
# https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-discovery

# fmt: off
_HID_REPORT_DESCRIPTOR = bytes((
    0x06, 0xD0, 0xF1,   # HID_Collection ( HID_Application ),
    0x09, 0x01,         # HID_Usage ( FIDO_USAGE_DATA ),
    0xA1, 0x01,         # HID_Collection ( HID_Application ),
    0x09, 0x20,         # HID_Usage ( FIDO_USAGE_DATA_IN ),
    0x15, 0x00,         # HID_LogicalMin ( 0 ),
    0x26, 0xFF, 0x00,   # HID_LogicalMaxS ( 0xff ),
    0x75, 0x08,         # HID_ReportSize ( 8 ),
    0x95, 0x40,         # HID_ReportCount ( HID_INPUT_REPORT_BYTES ),
    0x81, 0x02,         # HID_Input ( HID_Data | HID_Absolute | HID_Variable ),
    0x09, 0x21,         # HID_Usage ( FIDO_USAGE_DATA_OUT ),
    0x15, 0x00,         # HID_LogicalMin ( 0 ),
    0x26, 0xFF, 0x00,   # HID_LogicalMaxS ( 0xff ),
    0x75, 0x08,         # HID_ReportSize ( 8 ),
    0x95, 0x40,         # HID_ReportCount ( HID_OUTPUT_REPORT_BYTES ),
    0x91, 0x02,         # HID_Output ( HID_Data | HID_Absolute | HID_Variable ),
    0xC0,               # HID_EndCollection
))
# fmt: on

_FIDO_USAGE_PAGE = 0xF1D0
_FIDO_USAGE = 0x01

REPORT_LEN = 0x40


def initialize() -> None:
    log.debug("Creating fido device")
    fidoKey = usb_hid.Device(
        report_descriptor=_HID_REPORT_DESCRIPTOR,
        usage_page=_FIDO_USAGE_PAGE,
        usage=_FIDO_USAGE,
        report_ids=(0x00,),
        in_report_lengths=(REPORT_LEN,),
        out_report_lengths=(REPORT_LEN,),
    )

    log.debug("Setting fido key as the only hid enabled device")
    usb_hid.enable([fidoKey])


def get_device() -> usb_hid.Device:
    if "_device" in get_device.__dict__:
        return get_device._device

    for device in usb_hid.devices:
        log.debug(f"Found available device: ({device.usage_page}, {device.usage})")
        if device.usage_page == _FIDO_USAGE_PAGE and device.usage == _FIDO_USAGE:
            log.debug("FIDO device has been found")
            get_device._device = device
            return device

    assert False, "FIDO device has not been found"


async def send(cid: bytes, cmd: int, payload: bytes, device=None) -> None:
    if device is None:
        device = get_device()

    assert len(cid) == 4, "CID length is not equal to 4"

    bcnth = len(payload) >> 8
    bcntl = len(payload) & 0xFF

    seq = 0
    while len(payload) > 0:
        if seq == 0:
            # initialization packet
            buffer = cid
            buffer += cmd.to_bytes(1, "big")
            buffer += bcnth.to_bytes(1, "big")
            buffer += bcntl.to_bytes(1, "big")
        else:
            # continuation packet
            buffer = cid
            buffer += (seq | 0x80).to_bytes(1, "big")

        payload_len = REPORT_LEN - len(buffer)

        buffer += payload[:payload_len]
        payload = payload[payload_len:]

        if len(buffer) < REPORT_LEN:
            buffer += b"\x00" * (REPORT_LEN - len(buffer))

        assert len(buffer) == REPORT_LEN, "Packet size is not equal to REPORT_LEN"
        device.send_report(buffer)
        seq += 1
        assert seq < 0x80, "Sequence number is too big"

        await asyncio.sleep(0)


def receive(device: usb_hid.Device = None) -> Optional[CtapCommand]:
    if device is None:
        device = get_device()

    """
    https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-transactions

    The application channel that manages to get through the first initialization packet when the device
    is in idle state will keep the device locked for other channels until the last packet of the response
    message has been received or the transaction is aborted. The device then returns to idle state,
    ready to perform another transaction for the same or a different channel. Between two transactions,
    no state is maintained in the device and a host application must assume that any other process may
    execute other transactions at any time.
    """

    seq = 0
    cid = None
    cmd = None
    payload = b""
    payload_len = 0

    while True:
        buffer = device.get_last_received_report()
        if buffer == None:
            return None

        if len(buffer) != REPORT_LEN:
            raise CtapError(
                Error.INVALID_LENGTH,
                "Invalid packet length. Should be %d bytes, instead got %d bytes"
                % (REPORT_LEN, len(buffer)),
            )

        continuation_packet_flag = (
            buffer[4] & 0x80 != 0
        )  # if 7th bit set to 1 then it is a continuation packet

        if cid == None:
            cid = buffer[0:4]
        else:
            b4 = buffer[4]
            if (
                cid != buffer[0:4]
                and continuation_packet_flag
                and b4 == CtaphidCmd.INIT
            ):
                nonce = buffer[7 : 7 + 8]
                raise AbortError(cid, nonce)
            elif cid != buffer[0:4]:
                raise CtapError(
                    Error.INVALID_CHANNEL,
                    "Invalid channel ID %s" % cid.hex(),
                )

        if seq == 0 and continuation_packet_flag:
            raise CtapError(
                Error.INVALID_SEQ,
                "Invalid sequence number, expected 0 for initialization packet",
            )

        if seq > 0 and not continuation_packet_flag:
            raise CtapError(
                Error.INVALID_SEQ,
                "Invalid sequence number, expected > 0 for continuation packet",
            )
        if not continuation_packet_flag:
            cmd = buffer[4]

            payload_len = (buffer[5] << 8) + buffer[6]

            payload += buffer[7:]
        else:
            if cid != buffer[0:4]:
                raise CtapError(
                    Error.INVALID_CHANNEL,
                    "Invalid channel ID %s" % cid.hex(),
                )
            payload += buffer[5:]

        if len(payload) >= payload_len:
            break

        seq += 1

    payload = payload[:payload_len]

    return CtapCommand(cid, cmd, payload)
