import os
import typing

import adafruit_logging as logging

import circuitkey.crypto as crypto
from circuitkey.error import CborError
from circuitkey.schema import Error
from circuitkey.storage import Bucket
from circuitkey.util import next_tick

log = logging.getLogger(__name__)


class PinProtocolV1:
    def __init__(self, storage: Bucket = Bucket("pin.json")):
        self._storage = storage

        data = self._load()

        self._pin = data[0]
        self._retry_count = data[1]

        self._pin_token = os.urandom(16)
        self._pin_mismatch_counter = 0

        self._key_agreement_key = crypto.ec_genkey()

    def _load(self) -> typing.Tuple[bytes | None, int | None]:
        data = self._storage.load()

        return (
            data["pin"] if "pin" in data else None,
            data["retry_count"] if "retry_count" in data else 8,
        )

    def _save(self) -> None:
        self._storage.save({"pin": self._pin, "retry_count": self._retry_count})

    def _validate(self, pin: bytes) -> None:
        if len(pin) < 4:
            raise CborError(Error.PIN_POLICY_VIOLATION, "PIN too short")

        if len(pin) > 63:
            raise CborError(Error.PIN_POLICY_VIOLATION, "PIN too long")

    async def verify(self, pin_hash_enc: bytes, platform_bG: crypto.ECPubKey) -> bytes:
        """
        Verify PIN. The PIN is encrypted with the shared secret by platform.
        The authenticator decrypts the PIN and verifies it.

        :param pin_hash_enc: encrypted PIN
        :param platform_bG: platform public key
        :return: PIN token
        """

        def is_device_blocked():
            if self._pin_mismatch_counter >= 3:
                raise CborError(Error.PIN_AUTH_BLOCKED, "PIN auth blocked")

            if self._retry_count <= 0:
                raise CborError(Error.PIN_BLOCKED, "PIN is blocked")

        is_device_blocked()

        if self._retry_count <= 0:
            raise CborError(Error.PIN_BLOCKED, "PIN is blocked")

        key_agreement_key_a = self._key_agreement_key[1]
        sharedSecret = await next_tick(crypto.ec_shared_secret)(
            key_agreement_key_a, platform_bG
        )

        pin_hash = await next_tick(crypto.hmac_sha256)(sharedSecret, pin_hash_enc)
        pin_hash = pin_hash[:16]

        self._retry_count -= 1
        self._save()

        if pin_hash != self._pin:
            # new key pair for each attempt
            self.key_agreement_key = await next_tick(crypto.ec_genkey)()
            self._pin_mismatch_counter += 1

            is_device_blocked()

            raise CborError(Error.PIN_INVALID, "PIN is invalid")

        self._pin_mismatch_counter = 0
        self._retry_count = 8
        self._save()

        enc_pin_token = await next_tick(crypto.aes256_cbc_encrypt)(
            self._pin_token, sharedSecret, 32
        )
        return enc_pin_token

    async def set_pin(
        self,
        new_enc_pin: bytes,
        pin_auth: bytes,
        platform_bG: crypto.ECPubKey,
    ) -> None:
        """
        Set a new PIN. The PIN is encrypted with the shared secret by platform.
        The authenticator decrypts the PIN and verifies the PIN auth.
        PIN is never fully stored (only first 16 bytes of hash).

        :param new_enc_pin: encrypted PIN
        :param pin_auth: PIN auth
        :param platform_bG: platform public key
        """
        key_agreement_key_a = self._key_agreement_key[1]
        sharedSecret = await next_tick(crypto.ec_shared_secret)(
            key_agreement_key_a, platform_bG
        )

        pin_hash_enc = await next_tick(crypto.hmac_sha256)(sharedSecret, new_enc_pin)
        pin_hash_enc = pin_hash_enc[:16]

        if pin_hash_enc != pin_auth:
            raise CborError(Error.PIN_AUTH_INVALID, "PIN mismatch")

        zero_padded_pin = await next_tick(crypto.aes256_cbc_decrypt)(
            sharedSecret, new_enc_pin
        )
        pin = zero_padded_pin[: zero_padded_pin.find(b"\x00")]

        self._validate(pin)

        self._pin = await next_tick(crypto.sha256)(pin)
        self._pin = self._pin[:16]
        self._pin_token = os.urandom(16)

        self._save()

    def is_pin_set(self) -> bool:
        """
        Check if PIN is set.
        """
        return self._pin is not None

    def get_retries(self) -> int:
        """
        Number of retries left.
        """
        return self._retry_count

    def is_blocked(self) -> bool:
        """
        Nothing can be done. The authenticator is blocked.
        """
        return self._retry_count <= 0

    def is_temporarily_blocked(self) -> bool:
        """
        Requires a power cycle to reset.
        """
        return self._pin_mismatch_counter >= 3

    def get_key_agreement_pub_key(self) -> crypto.ECPubKey:
        """
        Get public key for key agreement.
        """
        return self._key_agreement_key[0]


def get_pin_protocol(protocol_version: int = 1) -> PinProtocolV1:
    if protocol_version == 1:
        if "v1" not in get_pin_protocol.__dict__:
            get_pin_protocol.v1 = PinProtocolV1()
        return get_pin_protocol.v1

    log.error("Only V1 PIN protocol is currently supported")

    raise CborError(Error.PIN_AUTH_INVALID, "PIN protocol not supported")
