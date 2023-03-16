import asyncio
import pytest
import sys

from unittest.mock import MagicMock
from async_button import SimpleButton
from pytest_mock import MockerFixture

sys.modules["usb_hid"] = MagicMock()
sys.modules["countio"] = MagicMock()

import circuitkey.ui as ui


@pytest.fixture
def btn(mocker: MockerFixture):
    return mocker.patch("async_button.SimpleButton", autospec=SimpleButton)


@pytest.fixture
def pulsar():
    return ui.LedPulsar(0, 0, 0)


@pytest.fixture(autouse=True)
def setup_teardown(mocker: MockerFixture):
    mocker.patch("digitalio.DigitalInOut")

    yield


async def for_led_off(pulsar: ui.LedPulsar):
    async def wait_for_led_off(pulsar: ui.LedPulsar):
        while pulsar.led.value:
            await asyncio.sleep(0)

    await asyncio.wait_for(wait_for_led_off(pulsar), timeout=1)
    return


@pytest.mark.asyncio
async def test_verify_user_presence_timeout(
    btn: MagicMock, pulsar: ui.LedPulsar, mocker: MockerFixture
):
    async def no_button_pressed():
        while True:
            await asyncio.sleep(0)

    mocker.patch.object(btn, "pressed", wraps=no_button_pressed)

    u = ui.UI(btn, pulsar)

    with pytest.raises(asyncio.TimeoutError):
        await u.verify_user_presence(timeout=0)

    await for_led_off(pulsar)

    assert pulsar.is_off()


@pytest.mark.asyncio
async def test_verify_user_presence_button_pressed(
    btn: MagicMock, pulsar: ui.LedPulsar, mocker: MockerFixture
):
    async def button_pressed():
        await asyncio.sleep(0)

    mocker.patch.object(btn, "pressed", wraps=button_pressed)

    u = ui.UI(btn, pulsar)

    # no error raised, so we're good - user pressed the button
    await u.verify_user_presence(timeout=5)

    await for_led_off(pulsar)

    assert pulsar.is_off()
