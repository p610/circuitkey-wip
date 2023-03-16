from adafruit_logging import getLogger
from circuitkey.hid import initialize

log = getLogger("boot")

# import storage
# log.info("Disabling storage")
# storage.disable_usb_drive()

log.info("Starting hid initialization")
initialize()

log.info("Boot completed")
