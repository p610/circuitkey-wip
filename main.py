import asyncio
import adafruit_logging as logging
from circuitkey import ctaphid
from circuitkey.error import AbortError, CtapError

import circuitkey.hid as hid
import circuitkey.ui as ui


# configure root logger
logging.getLogger("").setLevel(logging.DEBUG)


async def main():
    log = logging.getLogger(__name__)

    log.info("Starting authenticator...")

    hdev = hid.get_device()

    user_interface = ui.get_ui()

    # Say hello to the user
    await user_interface.wink()

    log.info("Device is ready")

    while True:
        try:
            await asyncio.sleep(0)
            data = hid.receive(hdev)
        except AbortError as e:
            log.error(
                "Received abort command for cid [%d] with nonce [%s]", e.cid, e.nonce
            )
            await ctaphid.abort_cmd(hdev, e.cid, e.nonce)
            continue
        except CtapError as e:
            log.error(
                "Unable to receive message from HID due to following error: %s", e
            )
            await ctaphid.error_cmd(hdev, e.cid, e.code)
            continue

        log.debug(
            "Received command [%d] for cid [%d] with payload length %d",
            data.cmd,
            data.cid,
            len(data.payload),
        )

        asyncio.create_task(
            ctaphid.process(hid, data.cid, data.cmd, data.payload), "CtapProcessorTask"
        )


asyncio.run(main())
