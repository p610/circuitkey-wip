from collections import namedtuple

from enum import IntFlag, unique

CtapCommand = namedtuple("CtapCommand", ["cid", "cmd", "payload"])


# Error codes
# https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses


@unique
class Error(IntFlag):
    INVALID_COMMAND = 0x01  # Invalid command.
    INVALID_PARAMETER = 0x02  # Invalid parameter.
    INVALID_LENGTH = 0x03  # Invalid message length.
    INVALID_SEQ = 0x04  # Invalid message sequencing.
    TIMEOUT = 0x05  # Message timed out.
    CHANNEL_BUSY = 0x06  # Channel busy.
    LOCK_REQUIRED = 0x0A  # Command requires channel lock.
    INVALID_CHANNEL = 0x0B  # Invalid channel.

    CBOR_UNEXPECTED_TYPE = 0x11  # Invalid/unexpected CBOR error
    INVALID_CBOR = 0x12  # Error when parsing CBOR.
    MISSING_PARAMETER = 0x14  # Missing non-optional parameter.
    LIMIT_EXCEEDED = 0x15  # Limit for number of items exceeded.
    UNSUPPORTED_EXTENSION = 0x16  # Unsupported extension.
    CREDENTIAL_EXCLUDED = 0x19  # Valid credential found in the exclude list.
    PROCESSING = 0x21  # Processing (Lengthy operation is in progress).
    INVALID_CREDENTIAL = 0x22  # Credential not valid for the authenticator.
    USER_ACTION_PENDING = 0x23  # Authentication is waiting for user interaction.
    OPERATION_PENDING = 0x24  # Processing, lengthy operation is in progress.
    NO_OPERATIONS = 0x25  # No operations are pending.
    UNSUPPORTED_ALGORITHM = 0x26  # Unsupported algorithm or parameter.
    OPERATION_DENIED = 0x27  # Operation denied (e.g. locked, disabled, etc.).
    KEY_STORE_FULL = 0x28  # Internal key storage is full.
    NO_OPERATION_PENDING = 0x2A  # No outstanding operations.
    UNSUPPORTED_OPTION = 0x2B  # Unsupported option.
    INVALID_OPTION = 0x2C  # Not a valid option for current operation.
    KEEPALIVE_CANCEL = 0x2D  # Pending keep alive was cancelled.
    NO_CREDENTIALS = 0x2E  # No valid credentials provided.
    USER_ACTION_TIMEOUT = 0x2F  # Timeout waiting for user interaction.
    NOT_ALLOWED = 0x30  # Continuation command, such as, authenticatorGetNextAssertion not allowed.
    PIN_INVALID = 0x31  # PIN Invalid.
    PIN_BLOCKED = 0x32  # PIN Blocked.
    PIN_AUTH_INVALID = 0x33  # PIN authentication,pinAuth, verification failed.
    PIN_AUTH_BLOCKED = (
        0x34  # PIN authentication,pinAuth, blocked. Requires power recycle to reset.
    )
    PIN_NOT_SET = 0x35  # No PIN has been set.
    PUAT_REQUIRED = 0x36  # PIN is required for the selected operation.
    PIN_POLICY_VIOLATION = 0x37  # PIN policy violation. For example, the PIN provided is too long or too short.
    PIN_TOKEN_EXPIRED = 0x38  # PIN Token expired.
    REQUEST_TOO_LARGE = 0x39  # Request too large.
    ACTION_TIMEOUT = 0x3A  # Action timeout.
    UP_REQUIRED = 0x3B  # Up required.

    to_byte = lambda self: self.value.to_bytes(1, "big")

    is_ctap_error = lambda self: self.value <= 0x0B

    is_cbor_error = lambda self: self.value >= 0x0B


@unique
class KeepaliveStatusCode(IntFlag):
    PROCESSING = 1  # The authenticator is still processing the current request.
    UPNEEDED = 2  # The authenticator is waiting for user presence.

    to_byte = lambda self: self.value.to_bytes(1, "big")


@unique
class CapabiltyCode(IntFlag):
    WINK = 0x01  # If set to 1, authenticator implements CTAPHID_WINK function
    CBOR = 0x04  # If set to 1, authenticator implements CTAPHID_CBOR function
    NMSG = 0x08  # If set to 1, authenticator DOES NOT implement CTAPHID_MSG function

    @classmethod
    def to_byte(cls, *args):
        return sum(args).to_bytes(1, "big")


@unique
class CtaphidCmd(IntFlag):
    PING = 0x01
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11
    KEEPALIVE = 0x3B
    ERROR = 0x3F


@unique
class CborCmd(IntFlag):
    MAKE_CREDENTIAL = 0x01
    GET_ASSERTION = 0x02
    GET_NEXT_ASSERTION = 0x08
    GET_INFO = 0x04
    CLIENT_PIN = 0x06
    RESET = 0x07


@unique
class PinSubCmd(IntFlag):
    GET_RETRIES = 0x01
    GET_KEY_AGREEMENT = 0x02
    SET_NEW = 0x03
    CHANGE = 0x04
    GET_TOKEN = 0x05


CTAPHID_BROADCAST_CID = int(0xFFFFFFFF).to_bytes(4, "big")

CBOR_SUCCCESS_CODE = 0x00


def cbor_pin_response(retries=None, key_agreement=None, pin_token=None):
    response = {}

    if retries is not None:
        response[0x03] = retries

    if key_agreement is not None:
        response[0x01] = key_agreement

    if pin_token is not None:
        response[0x02] = pin_token

    return response if len(response) > 0 else None
