import ecdsa
import pytest

from circuitkey import crypto, storage
from circuitkey.error import CborError
from circuitkey.pin import PinProtocolV1
from circuitkey.schema import Error

PIN = b"\x03\xacgB\x16\xf3\xe1\\v\x1e\xe1\xa5\xe2U\xf0g"
PIN_AUTH = b"`N\xb7\xc6\x9b@}\xc7Bw\x98\x88\xef<K\x9e"
PIN_HASH_ENC = b"5\xa4(\xc3\x15s\\\xea<\xc8\xd2\xec\xe4\xdb\x07\xd9\xdaQ`ctf2[I`\x85Hs\x82\xe6l$|\t\xdc\r\x0c\xdb\xd7\xda\xb6\xd1\xe2\xdc\xab/\xec1!)-\xeb9fw\x1di\x1c\xae\xb0\xf5\xb5\x9f"

PLATFORM_KEY = (
    b"""-----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDTXsa7PHfIjG9acnr3Njni5+plwB
    MDONXaADoWNtTjLwX53dV+wPWggj9lAgILIFY5vgvfZe1NE74OFY9GBbvg==
    -----END PUBLIC KEY-----
    """,
    b"""-----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIOyVQrV5WlpBUHlbc00aVt+7KoQ5N5MnGVWNUyWCM09joAoGCCqGSM49
    AwEHoUQDQgAEDTXsa7PHfIjG9acnr3Njni5+plwBMDONXaADoWNtTjLwX53dV+wP
    Wggj9lAgILIFY5vgvfZe1NE74OFY9GBbvg==
    -----END EC PRIVATE KEY-----
    """,
)

AUTHENTICATOR_KEY = (
    b"""-----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHcuQC4BEyiTNuUeEofHqcCNWIMfM
    dcfUqfrrmpfjFs7GuVpTqT/QXTOEL2y28HIsl7msvs3GbEbQErnBQm1otw==
    -----END PUBLIC KEY-----
    """,
    b"""-----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIOSV9ZV9xgktBeUGbhRsTuY4vf3IUYD0voHMRMOrtkCNoAoGCCqGSM49
    AwEHoUQDQgAEHcuQC4BEyiTNuUeEofHqcCNWIMfMdcfUqfrrmpfjFs7GuVpTqT/Q
    XTOEL2y28HIsl7msvs3GbEbQErnBQm1otw==
    -----END EC PRIVATE KEY-----
    """,
)


def to_ec_key(keys):
    pub = ecdsa.VerifyingKey.from_pem(keys[0]).pubkey.point
    return crypto.ECPubKey(pub.x(), pub.y()), keys[1]


class InMemBucket(storage.Bucket):
    def __init__(self):
        self._data = {}

    def load(self):
        return self._data

    def save(self, data):
        self._data = data


@pytest.fixture
def in_mem_bucket():
    return InMemBucket()


@pytest.fixture
def pin_protocol_v1(in_mem_bucket: InMemBucket):
    return PinProtocolV1(in_mem_bucket)


async def setup_device_with_new_pin(pin_protocol_v1: PinProtocolV1, pin: bytes):
    platform_bG, platform_b = crypto.ec_genkey()
    authenticator_aG = pin_protocol_v1.get_key_agreement_pub_key()

    # platform generates shared secret
    shared_secret = crypto.ec_shared_secret(platform_b, authenticator_aG)

    # platform encrypts PIN with shared secret
    pin_hash_enc = crypto.aes256_cbc_encrypt(shared_secret, pin, 64)

    # platform generates pin_auth
    pin_auth = crypto.hmac_sha256(shared_secret, pin_hash_enc)[:16]

    # platform sends pin_hash_enc and pin_auth to authenticator
    await pin_protocol_v1.set_pin(pin_hash_enc, pin_auth, platform_bG)

    return (shared_secret, pin_auth)


@pytest.mark.asyncio
async def test_should_set_new_pin(pin_protocol_v1: PinProtocolV1):
    pin = "1234".encode("UTF-8")

    await setup_device_with_new_pin(pin_protocol_v1, pin)

    assert pin_protocol_v1._pin == crypto.sha256(pin)[:16]
    assert pin_protocol_v1._retry_count == 8


@pytest.mark.asyncio
async def test_should_fail_set_new_pin_if_pin_lenght_incorrect(
    pin_protocol_v1: PinProtocolV1,
):
    pin = "123".encode("UTF-8")

    with pytest.raises(CborError) as e:
        await setup_device_with_new_pin(pin_protocol_v1, pin)
        assert e.code == Error.PIN_POLICY_VIOLATION


@pytest.mark.asyncio
async def ignore_test_should_change_pin(pin_protocol_v1: PinProtocolV1):  # TODO fixme
    pin_protocol_v1._pin = PIN_AUTH
    pin_protocol_v1._retry_count = 6
    pin_protocol_v1._pin_mismatch_counter = 2
    pin_protocol_v1._key_agreement_key = to_ec_key(AUTHENTICATOR_KEY)

    new_pin = "5678".encode("UTF-8")
    shared_secret = crypto.ec_shared_secret(
        to_ec_key(PLATFORM_KEY)[1], to_ec_key(AUTHENTICATOR_KEY)[0]
    )
    new_enc_pin = crypto.aes256_cbc_encrypt(shared_secret, new_pin, 64)

    await pin_protocol_v1.set_pin(
        new_enc_pin, PIN_AUTH, platform_bG=to_ec_key(PLATFORM_KEY)[0]
    )

    assert pin_protocol_v1._pin == 1
    assert pin_protocol_v1._retry_count == 8


@pytest.mark.asyncio
async def test_should_verify_pin(pin_protocol_v1: PinProtocolV1):
    pin_protocol_v1._pin = PIN_AUTH
    pin_protocol_v1._retry_count = 6
    pin_protocol_v1._pin_mismatch_counter = 2
    pin_protocol_v1._key_agreement_key = to_ec_key(AUTHENTICATOR_KEY)

    pin_token = await pin_protocol_v1.verify(PIN_HASH_ENC, to_ec_key(PLATFORM_KEY)[0])

    assert len(pin_token) == 32
    assert pin_protocol_v1.get_retries() == 8
    assert pin_protocol_v1._pin_mismatch_counter == 0


@pytest.mark.asyncio
async def test_should_fail_pin_verification(pin_protocol_v1: PinProtocolV1):
    pin_protocol_v1._pin = b"000000"
    pin_protocol_v1._retry_count = 6
    pin_protocol_v1._pin_mismatch_counter = 0
    pin_protocol_v1._key_agreement_key = to_ec_key(AUTHENTICATOR_KEY)

    with pytest.raises(CborError) as e:
        await pin_protocol_v1.verify(PIN_HASH_ENC, to_ec_key(PLATFORM_KEY)[0])
        assert e.code == Error.PIN_INVALID

    assert pin_protocol_v1.get_retries() == 5
    assert pin_protocol_v1._pin_mismatch_counter == 1


@pytest.mark.asyncio
async def test_should_block_auth_after_too_many_failed_attempts(
    pin_protocol_v1: PinProtocolV1,
):
    pin_protocol_v1._pin = "000000".encode("UTF-8")
    pin_protocol_v1._retry_count = 1
    pin_protocol_v1._pin_mismatch_counter = 3
    pin_protocol_v1._key_agreement_key = to_ec_key(AUTHENTICATOR_KEY)

    with pytest.raises(CborError) as e:
        await pin_protocol_v1.verify(PIN_HASH_ENC, to_ec_key(PLATFORM_KEY)[0])
        assert e.code == Error.PIN_BLOCKED

    assert pin_protocol_v1.get_retries() == 1


@pytest.mark.asyncio
async def test_should_block_device_after_too_many_retries(
    pin_protocol_v1: PinProtocolV1,
):
    pin_protocol_v1 = PinProtocolV1(InMemBucket())
    pin_protocol_v1._pin = "000000".encode("UTF-8")
    pin_protocol_v1._retry_count = 0
    pin_protocol_v1._pin_mismatch_counter = 0
    pin_protocol_v1._key_agreement_key = to_ec_key(AUTHENTICATOR_KEY)

    with pytest.raises(CborError) as e:
        await pin_protocol_v1.verify(PIN_HASH_ENC, to_ec_key(PLATFORM_KEY)[0])
        assert e.code == Error.PIN_AUTH_BLOCKED

    assert pin_protocol_v1.get_retries() == 0
