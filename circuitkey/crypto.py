import typing
import hmac
import adafruit_hashlib as hashlib

from collections import namedtuple
from ecdsa import SigningKey, VerifyingKey, NIST256p
from ecdsa.ecdh import ECDH
from ecdsa.ellipticcurve import Point


def aes256_cbc_encrypt(key: bytes, data: bytes, buffer_size: int) -> bytes:
    if len(data) > buffer_size:
        raise ValueError("Data too large [{} > {}]".format(len(data), buffer_size))

    if buffer_size % 16 != 0:
        raise ValueError("Buffer size must be a multiple of 16 - AES Block")

    data = data + b"\x00" * (buffer_size - len(data))

    try:
        import aesio

        cipher = aesio.AES(key, aesio.MODE_CBC)

        output = bytearray(buffer_size)
        cipher.encrypt_into(data, output)
        return output
    except ModuleNotFoundError:
        # fallback to pure python implementation
        # if aesio is not available (e.g. unittests)

        from cryptography.hazmat.primitives.ciphers.algorithms import AES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.backends import default_backend

        cipher = Cipher(AES(key), modes.CBC(b"\x00" * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()


def aes256_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    try:
        import aesio

        cipher = aesio.AES(key, aesio.MODE_CBC)

        output = bytearray(64)
        cipher.decrypt_into(data, output)
        return output
    except ModuleNotFoundError:
        # fallback to pure python implementation
        # if aesio is not available (e.g. unittests)
        from cryptography.hazmat.primitives.ciphers.algorithms import AES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.backends import default_backend

        cipher = Cipher(AES(key), modes.CBC(b"\x00" * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()


def hmac_sha256(msg: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, msg=msg, digestmod=hashlib.sha256).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


ECPubKey = namedtuple("ECPubKey", ["x", "y"])
ECPrivKey = bytes


def ec_genkey() -> typing.Tuple[ECPubKey, ECPrivKey]:
    # TODO does not work with CircuitPython needs to be replaced with C implementation
    sk = SigningKey.generate(NIST256p)
    point = sk.verifying_key.pubkey.point
    return ECPubKey(point.x(), point.y()), sk.to_pem()


def ec_shared_secret(private_key: ECPrivKey, public_key: ECPubKey) -> bytes:
    curve = NIST256p

    priv = SigningKey.from_pem(private_key)
    pub = VerifyingKey.from_public_point(
        Point(curve=curve.curve, x=public_key.x, y=public_key.y), curve=curve
    )

    ecdh = ECDH(curve=curve, private_key=priv, public_key=pub)
    return hashlib.sha256(ecdh.generate_sharedsecret_bytes()).digest()
