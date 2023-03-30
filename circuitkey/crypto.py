import hmac
import typing
from collections import namedtuple

import adafruit_hashlib as hashlib
import adafruit_logging as logging

logger = logging.getLogger(__name__)

ECPubKey = namedtuple("ECPubKey", ["x", "y"])
ECPrivKey = bytes


class Backend:
    def aes256_cbc_encrypt(self, key: bytes, data: bytes, buffer_size: int) -> bytes:
        raise NotImplementedError()

    def aes256_cbc_decrypt(self, key: bytes, data: bytes) -> bytes:
        raise NotImplementedError()

    def hmac_sha256(self, msg: bytes, secret: bytes) -> bytes:
        return hmac.new(secret, msg=msg, digestmod=hashlib.sha256).digest()

    def sha256(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def ec_genkey(self) -> typing.Tuple[ECPubKey, ECPrivKey]:
        raise NotImplementedError()

    def ec_shared_secret(self, private_key: ECPrivKey, public_key: ECPubKey) -> bytes:
        raise NotImplementedError()


class CircuitPythonBackend(Backend):
    def aes256_cbc_encrypt(self, key: bytes, data: bytes, buffer_size: int) -> bytes:
        import aesio

        cipher = aesio.AES(key, aesio.MODE_CBC)
        output = bytearray(buffer_size)
        cipher.encrypt_into(data, output)

        return output

    def aes256_cbc_decrypt(self, key: bytes, data: bytes) -> bytes:
        import aesio

        cipher = aesio.AES(key, aesio.MODE_CBC)
        output = bytearray(len(data))
        cipher.decrypt_into(data, output)

        return output

    def ec_genkey(self) -> typing.Tuple[ECPubKey, ECPrivKey]:
        import crypto

        pub_key, priv_key = crypto.gen_keys()
        x, y = pub_key[0].to_bytes(32, "big"), pub_key[1].to_bytes(32, "big")

        return ECPubKey(x, y), priv_key

    def ec_shared_secret(self, private_key: ECPrivKey, public_key: ECPubKey) -> bytes:
        import crypto

        x = public_key[0].to_bytes(32, "big")
        y = public_key[1].to_bytes(32, "big")

        return crypto.shared_secret(x, y, private_key)


class CPythonBackend(Backend):
    def aes256_cbc_encrypt(self, key: bytes, data: bytes, buffer_size: int) -> bytes:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.primitives.ciphers.algorithms import AES

        cipher = Cipher(AES(key), modes.CBC(b"\x00" * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def aes256_cbc_decrypt(self, key: bytes, data: bytes) -> bytes:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.primitives.ciphers.algorithms import AES

        cipher = Cipher(AES(key), modes.CBC(b"\x00" * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def ec_genkey(self) -> typing.Tuple[ECPubKey, ECPrivKey]:
        from ecdsa import NIST256p, SigningKey

        sk = SigningKey.generate(NIST256p)
        point = sk.verifying_key.pubkey.point
        return ECPubKey(point.x(), point.y()), sk.to_pem()

    def ec_shared_secret(self, private_key: ECPrivKey, public_key: ECPubKey) -> bytes:
        from ecdsa import NIST256p, SigningKey, VerifyingKey
        from ecdsa.ecdh import ECDH
        from ecdsa.ellipticcurve import Point

        curve = NIST256p

        priv = SigningKey.from_pem(private_key)
        pub = VerifyingKey.from_public_point(
            Point(curve=curve.curve, x=public_key.x, y=public_key.y), curve=curve
        )

        ecdh = ECDH(curve=curve, private_key=priv, public_key=pub)
        return hashlib.sha256(ecdh.generate_sharedsecret_bytes()).digest()


def backend():
    try:
        import aesio
        import crypto
    except ModuleNotFoundError:
        logger.info("Using CPython backend")
        return CPythonBackend()

    logger.info("Using CircuitPython backend")
    return CircuitPythonBackend()


def aes256_cbc_encrypt(key: bytes, data: bytes, buffer_size: int) -> bytes:
    if len(data) > buffer_size:
        raise ValueError("Data too large [{} > {}]".format(len(data), buffer_size))

    if buffer_size % 16 != 0:
        raise ValueError("Buffer size must be a multiple of 16 - AES Block")

    data = data + b"\x00" * (buffer_size - len(data))

    return _bcd.aes256_cbc_encrypt(key, data, buffer_size)


_bcd = backend()

# Add all the backend methods to the module
# so they can be used directly
# unless they are already defined
_methods = _bcd.__class__.__dict__.items()
_methods = filter(lambda x: not x[0].startswith("_"), _methods)
_methods = list(_methods) + list(  # include the super class methods
    filter(lambda x: x[0] not in [y[0] for y in _methods], Backend.__dict__.items())
)

wrap_method = lambda func: lambda *args, **kwargs: func(_bcd, *args, **kwargs)
for name, func in _methods:
    if name not in globals():
        globals()[name] = wrap_method(func)
