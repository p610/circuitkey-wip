# User interface. At the moement only one LED and button are used.

from adafruit_logging import getLogger
import digitalio
import asyncio
import async_button

from circuitkey.util import wait_until_first_complete

log = getLogger(__name__)


class LedPulsar:
    def __init__(self, pin, duration=0.25, interval=1.5) -> None:
        self.led = digitalio.DigitalInOut(pin)
        self.led.switch_to_output()
        self.duration = duration
        self.interval = interval
        self.off()

    async def blink(self) -> None:
        self.led.value = True
        await asyncio.sleep(self.duration)
        self.led.value = False

    async def _blink_forever(self) -> None:
        log.debug("Starting infinite blinking...")
        try:
            while True:
                await self.blink()
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            self.off()
            log.debug("Cancelled blinking, led off")

    def blink_forever(self) -> asyncio.Task:
        return asyncio.create_task(self._blink_forever(), name="BlinkingPulsarTask")

    def off(self):
        self.led.value = False

    def is_off(self):
        return not self.led.value


class UI:
    def __init__(self, button: async_button.SimpleButton, pulsar: LedPulsar):
        self.button = button
        self.pulsar = pulsar

    async def wink(self, times=3):
        for _ in range(times):
            await self.pulsar.blink()

    async def verify_user_presence(self, timeout=30):
        log.info("Verifing user presence (timeout=%d)", timeout)

        blinking_led = self.pulsar.blink_forever()
        button_pressed = asyncio.create_task(
            self.button.pressed(), name="ButtonPressedTask"
        )

        try:
            done, _ = await wait_until_first_complete(
                blinking_led, button_pressed, timeout=timeout
            )
            if button_pressed in done:
                log.debug("User confirmed")
                return
            else:
                raise asyncio.TimeoutError("User did not confirm in time")
        finally:
            if not blinking_led.done():
                blinking_led.cancel()


def get_ui():
    if "_ui" not in get_ui.__dict__:
        import board

        button = async_button.SimpleButton(digitalio.DigitalInOut(board.D2))
        pulsar = LedPulsar(board.D13)
        get_ui._ui = UI(button, pulsar)

    return get_ui._ui
