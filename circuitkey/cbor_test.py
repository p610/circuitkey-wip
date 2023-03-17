import asyncio
import struct
import sys
from unittest.mock import MagicMock
import flynn
import pytest
import pytest_mock
from circuitkey.schema import CborCmd, CtapCommand, PinSubCmd, Error

sys.modules["countio"] = MagicMock()

import circuitkey.cbor as cbor
import circuitkey.info as info


@pytest.mark.asyncio
async def test_cbor_process_ok():
    command = CtapCommand(None, None, struct.pack("<B", CborCmd.GET_INFO))

    response = await cbor.process(command)

    assert response == (struct.pack("<B", 0x00) + flynn.dumps(info.CBOR_INFO))


@pytest.mark.asyncio
async def test_cbor_process_invalid_command():
    command = CtapCommand(None, None, struct.pack("<B", 0xFF))

    response = await cbor.process(command)

    assert response == struct.pack("<B", Error.INVALID_COMMAND)


@pytest.mark.asyncio
async def test_cbor_process_invalid_cbor():
    invalid_cbor = flynn.dumps({"a": "b", "c": "d"})[:7]
    cbor_payload = CborCmd.CLIENT_PIN.to_bytes(1, "big") + invalid_cbor
    command = CtapCommand(None, None, cbor_payload)

    response = await cbor.process(command)

    assert response == struct.pack("<B", Error.INVALID_CBOR)


@pytest.mark.asyncio
async def test_cbor_process_abort(mocker: pytest_mock.MockFixture):
    mocker.patch(
        "circuitkey.cbor.authenticator_make_credential",
        side_effect=asyncio.CancelledError(),
    )

    command = CtapCommand(
        None, None, struct.pack("<B", CborCmd.MAKE_CREDENTIAL) + flynn.dumps({})
    )

    response = await cbor.process(command)

    assert response == struct.pack("<B", Error.KEEPALIVE_CANCEL)


@pytest.mark.asyncio
async def test_reset_if_device_uptime_more_than_10_s(
    mocker: pytest_mock.MockFixture,
):
    mocker.patch("time.monotonic", return_value=11)

    with pytest.raises(cbor.CborError) as e:
        await cbor.authenticator_reset()
        assert e.code == Error.NOT_ALLOWED


@pytest.mark.asyncio
async def test_reset_user_presence_not_confirmed(mocker: pytest_mock.MockFixture):
    ui = MagicMock()
    ui.verify_user_presence.side_effect = asyncio.TimeoutError

    mocker.patch("time.monotonic", return_value=1)
    mocker.patch("circuitkey.ui.get_ui", return_value=ui)

    with pytest.raises(cbor.CborError) as e:
        await cbor.authenticator_reset()
        assert e.code == Error.USER_ACTION_TIMEOUT


@pytest.mark.asyncio
async def test_reset_ok(mocker: pytest_mock.MockFixture):
    ui = MagicMock()

    future = asyncio.Future()
    future.set_result(True)
    future.done = True

    ui.verify_user_presence.return_value = future
    mocker.patch("time.monotonic", return_value=1)
    mocker.patch("circuitkey.ui.get_ui", return_value=ui)
    storage_reset = mocker.patch("circuitkey.storage.reset")

    await cbor.authenticator_reset()

    storage_reset.assert_called_once()


@pytest.mark.asyncio
async def test_pin_retries(mocker: pytest_mock.MockFixture):
    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")
    pin_protocol.get_retries.return_value = 3

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    data = await cbor.authenticator_client_PIN(
        {
            "pinProtocol": 1,
            "subCommand": PinSubCmd.GET_RETRIES,
        }
    )

    assert data == {3: 3}


@pytest.mark.asyncio
async def test_pin_get_key_agreement(mocker: pytest_mock.MockFixture):
    x, y = 1, 2

    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")
    pin_protocol.get_key_agreement_pub_key.return_value = x, y

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    data = await cbor.authenticator_client_PIN(
        {
            "pinProtocol": 1,
            "subCommand": PinSubCmd.GET_KEY_AGREEMENT,
        }
    )
    assert data == {1: {1: 2, 3: -25, -1: 1, -2: x, -3: y}}


@pytest.mark.asyncio
async def test_pin_set_new_ok(mocker: pytest_mock.MockFixture):
    set_pin = asyncio.Future()
    set_pin.set_result(True)
    set_pin.done = True

    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")
    pin_protocol.is_pin_set.return_value = False
    pin_protocol.set_pin.return_value = set_pin

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    await cbor.authenticator_client_PIN(
        {
            "pinProtocol": 1,
            "subCommand": PinSubCmd.SET_NEW,
            "keyAgreement": {1: 2, 3: -25, -1: 1, -2: 1, -3: 2},
            "pinAuth": b"\x00" * 16,
            "newPinEnc": b"\x00" * 16,
        }
    )

    pin_protocol.set_pin.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing_param",
    ["pinProtocol", "subCommand", "keyAgreement", "pinAuth", "newPinEnc"],
)
async def test_pin_set_new_called_with_missing_parameter(
    mocker: pytest_mock.MockFixture, missing_param
):
    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")
    pin_protocol.is_pin_set.return_value = False

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    with pytest.raises(cbor.CborError) as e:
        req = {
            "pinProtocol": 1,
            "subCommand": PinSubCmd.SET_NEW,
            "keyAgreement": {1: 2, 3: -25, -1: 1, -2: 1, -3: 2},
            "pinAuth": b"\x00" * 16,
            "newPinEnc": b"\x00" * 16,
        }
        del req[missing_param]
        await cbor.authenticator_client_PIN(req)

        assert e.code == Error.INVALID_PARAMETER


@pytest.mark.asyncio
async def test_pin_set_new_called_but_pin_already_set(mocker: pytest_mock.MockFixture):
    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")
    pin_protocol.is_pin_set.return_value = True

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    with pytest.raises(cbor.CborError) as e:
        await cbor.authenticator_client_PIN({})

        assert e.code == Error.NOT_ALLOWED


@pytest.mark.asyncio
async def test_pin_change_ok(mocker: pytest_mock.MockFixture):
    set_pin = verify = asyncio.Future()
    set_pin.set_result(None)

    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")
    pin_protocol.verify.return_value = verify
    pin_protocol.set_pin.return_value = set_pin
    pin_protocol.get_retries.return_value = 3

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    await cbor.authenticator_client_PIN(
        {
            "pinProtocol": 1,
            "subCommand": PinSubCmd.CHANGE,
            "keyAgreement": {1: 2, 3: -25, -1: 1, -2: 1, -3: 2},
            "pinAuth": b"\x00" * 16,
            "newPinEnc": b"\x00" * 16,
            "pinHashEnc": b"\x00" * 16,
        }
    )

    pin_protocol.set_pin.assert_called_once()
    pin_protocol.verify.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing_param",
    ["pinProtocol", "subCommand", "keyAgreement", "pinAuth", "newPinEnc", "pinHashEnc"],
)
async def test_pin_change_called_with_missing_parameter(
    mocker: pytest_mock.MockFixture, missing_param: str
):
    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")
    pin_protocol.get_retries.return_value = 3

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    with pytest.raises(cbor.CborError) as e:
        req = {
            "pinProtocol": 1,
            "subCommand": PinSubCmd.CHANGE,
            "keyAgreement": {1: 2, 3: -25, -1: 1, -2: 1, -3: 2},
            "pinAuth": b"\x00" * 16,
            "newPinEnc": b"\x00" * 16,
            "pinHashEnc": b"\x00" * 16,
        }
        del req["pinHashEnc"]
        await cbor.authenticator_client_PIN(req)

        assert e.code == Error.INVALID_PARAMETER


@pytest.mark.asyncio
async def test_pin_token_ok(mocker: pytest_mock.MockFixture):
    verify = asyncio.Future()
    verify.set_result("HASH")

    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")
    pin_protocol.verify.return_value = verify

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    data = await cbor.authenticator_client_PIN(
        {
            "pinProtocol": 1,
            "subCommand": PinSubCmd.GET_TOKEN,
            "keyAgreement": {1: 2, 3: -25, -1: 1, -2: 1, -3: 2},
            "pinHashEnc": b"\x00" * 16,
        }
    )
    assert data == {2: "HASH"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing_param",
    ["pinProtocol", "subCommand", "keyAgreement", "pinHashEnc"],
)
async def test_pin_token_called_with_missing_parameter(
    mocker: pytest_mock.MockFixture, missing_param: str
):
    pin_protocol = mocker.patch("circuitkey.pin.PinProtocolV1")

    mocker.patch("circuitkey.pin.get_pin_protocol", return_value=pin_protocol)

    with pytest.raises(cbor.CborError) as e:
        req = {
            "pinProtocol": 1,
            "subCommand": PinSubCmd.GET_TOKEN,
            "keyAgreement": {1: 2, 3: -25, -1: 1, -2: 1, -3: 2},
            "pinHashEnc": b"\x00" * 16,
        }
        del req[missing_param]
        await cbor.authenticator_client_PIN(req)

        assert e.code == Error.INVALID_PARAMETER
