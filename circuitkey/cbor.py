import asyncio
import inspect
import struct
import time
import flynn
import flynn.decoder as decoder
from circuitkey import pin
from circuitkey.error import CborError

import circuitkey.info as info
import circuitkey.ui as ui
import circuitkey.storage as storage

from circuitkey.schema import (
    CBOR_SUCCCESS_CODE,
    CborCmd,
    CtapCommand,
    PinSubCmd,
    Error,
    cbor_pin_response,
)

from adafruit_logging import getLogger


log = getLogger(__name__)


async def authenticator_reset() -> None:
    """
    This method is used by the client to reset an authenticator back to a factory default state.
    """

    uptime_in_s = time.monotonic()

    if uptime_in_s > 10:
        raise CborError(
            Error.NOT_ALLOWED,
            "Device has been up for more than 10 seconds. Precisely: %d s"
            % uptime_in_s,
        )

    try:
        timeout_in_sec = 30
        await ui.get_ui().verify_user_presence(timeout_in_ms=timeout_in_sec * 1000)
    except asyncio.TimeoutError:
        raise CborError(
            Error.USER_ACTION_TIMEOUT,
            f"User did not confirm reset within {timeout_in_sec} seconds",
        )

    log.info("User confirmed reset")

    storage.reset()


def authenticator_get_info() -> tuple[Error, dict]:
    return info.CBOR_INFO


async def authenticator_make_credential(req):
    raise CborError(Error.NOT_ALLOWED, "Not implemented")


async def authenticator_get_assertion(req):
    raise CborError(Error.NOT_ALLOWED, "Not implemented")


async def authenticator_get_next_assertion():
    raise CborError(Error.NOT_ALLOWED, "Not implemented")


def pin_get_retries(req: dict):
    """
    5.5.3. Getting Retries from Authenticator
    """
    version = req.get("pinProtocol", 1)
    return cbor_pin_response(retries=pin.get_pin_protocol(version).get_retries())


def pin_get_key_agreement(req: dict):
    """
    5.5.4. Getting sharedSecret from Authenticator
    """
    version = req.get("pinProtocol", 1)
    public_key = pin.get_pin_protocol(version).get_key_agreement_pub_key()

    x, y = public_key

    key_agreement_aG = {1: 2, 3: -25, -1: 1, -2: x, -3: y}

    return cbor_pin_response(key_agreement=key_agreement_aG)


async def pin_set_new(req):
    """
    5.5.5. Setting a New PIN
    """
    pin_protocol = pin.get_pin_protocol(req.get("pinProtocol", 1))

    if pin_protocol.is_pin_set():
        raise CborError(Error.PIN_AUTH_INVALID, "PIN already set")

    try:
        key_agreement = req["keyAgreement"]
        new_pin_enc = req["newPinEnc"]
        pin_auth = req["pinAuth"]
    except KeyError as e:
        raise CborError(Error.MISSING_PARAMETER, e)

    await pin_protocol.set_pin(new_pin_enc, pin_auth, key_agreement)


async def pin_change(req):
    """
    5.5.6. Changing existing PIN
    """
    pin_protocol = pin.get_pin_protocol(req.get("pinProtocol", 1))

    if pin_protocol.get_retries() <= 0:
        raise CborError(Error.PIN_BLOCKED, "PIN is blocked")

    try:
        key_agreement = req["keyAgreement"]
        pin_hash_enc = req["pinHashEnc"]
        new_pin_enc = req["newPinEnc"]
        pin_auth = req["pinAuth"]
    except KeyError as e:
        raise CborError(Error.MISSING_PARAMETER, e)

    await pin_protocol.verify(pin_hash_enc, key_agreement)
    await pin_protocol.set_pin(new_pin_enc, pin_auth, key_agreement)


async def pin_get_token(req):
    """
    5.5.7. Getting pinToken from the Authenticator
    """
    try:
        key_agreement = req["keyAgreement"]
        pin_hash_enc = req["pinHashEnc"]
    except KeyError as e:
        raise CborError(Error.MISSING_PARAMETER, e)

    pin_protocol = pin.get_pin_protocol(req.get("pinProtocol", 1))
    pin_token = await pin_protocol.verify(pin_hash_enc, key_agreement)

    return cbor_pin_response(pin_token=pin_token)


async def authenticator_client_PIN(req):
    try:
        protocol = req["pinProtocol"]
        supported_protocols = info.CBOR_INFO["pinUvAuthProtocols"]
        sub_command = req["subCommand"]
    except KeyError as e:
        raise CborError(Error.MISSING_PARAMETER, e)

    assert protocol in supported_protocols, f"Unsupported PIN protocol: {protocol}"

    pin_sub_commands = {
        PinSubCmd.GET_RETRIES: pin_get_retries,
        PinSubCmd.GET_KEY_AGREEMENT: pin_get_key_agreement,
        PinSubCmd.SET_NEW: pin_set_new,
        PinSubCmd.CHANGE: pin_change,
        PinSubCmd.GET_TOKEN: pin_get_token,
    }

    pin_sub_command = pin_sub_commands.get(sub_command, None)

    if pin_sub_command is None:
        raise CborError(Error.INVALID_COMMAND, "Invalid PIN sub-command")
    else:
        result = pin_sub_command(req)
        if inspect.iscoroutine(result):
            return await result
        return result


async def process(cmd: CtapCommand) -> bytes:
    # structure: function, command, has_payload
    CBOR_COMMANDS = (
        (authenticator_make_credential, CborCmd.MAKE_CREDENTIAL, True),
        (authenticator_get_assertion, CborCmd.GET_ASSERTION, True),
        (
            authenticator_get_next_assertion,
            CborCmd.GET_NEXT_ASSERTION,
            True,
        ),
        (authenticator_get_info, CborCmd.GET_INFO, False),
        (authenticator_client_PIN, CborCmd.CLIENT_PIN, True),
        (authenticator_reset, CborCmd.RESET, False),
    )

    def encode_cbor_error(error: CborError | Error):
        return struct.pack("<B", error if isinstance(error, Error) else error.code)

    try:
        cbor_cmd = int(cmd.payload[0])
        log.info("Processing CBOR command: %s", hex(cbor_cmd))

        cbor_command = [c for c in CBOR_COMMANDS if c[1] == cbor_cmd]
        if len(cbor_command) == 0:
            log.error("Command not supported: %s", hex(cbor_cmd))
            return encode_cbor_error(Error.INVALID_COMMAND)

        assert len(cbor_command) == 1, "Command must be unique"

        processor, _, has_parameters = cbor_command[0]

        proc = None
        if has_parameters:
            cbor_encoded_paylod = cmd.payload[1:]
            try:
                await asyncio.sleep(0)
                payload = flynn.loads(cbor_encoded_paylod)
            except decoder.InvalidCborError as e:
                log.error("Invalid CBOR payload: %s", e)
                return struct.pack("<B", Error.INVALID_CBOR)

            log.debug("CBOR request: %s", payload)

            proc = processor(payload)
        else:
            proc = processor()

        try:
            await asyncio.sleep(0)

            # TODO: make sure that it does exist in circuitpython
            if inspect.iscoroutine(proc):
                resp = await proc
            else:
                resp = proc

        except CborError as e:
            log.error("CBOR error: %s occured during processing CBOR command", e)
            return encode_cbor_error(e)

        payload = resp

        log.info("Finsihed processing CBOR command: %s", hex(cbor_cmd))

        if payload != None:
            log.debug("CBOR response: %s", payload)

            await asyncio.sleep(0)
            cbor_encoded_payload = flynn.dumps(payload)

            return struct.pack("<B", CBOR_SUCCCESS_CODE) + cbor_encoded_payload
        else:
            log.debug("No CBOR response")
            return struct.pack("<B", CBOR_SUCCCESS_CODE)

    except asyncio.CancelledError:
        log.error("Cancelled, responding with CTAP2_ERR_KEEPALIVE_CANCEL")
        return struct.pack("<B", Error.KEEPALIVE_CANCEL)
