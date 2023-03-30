import circuitkey.crypto as crypto


def test_if_backend_methods_are_exported():
    assert hasattr(crypto, "aes256_cbc_encrypt")
    assert hasattr(crypto, "aes256_cbc_decrypt")

    assert hasattr(crypto, "ec_genkey")
    assert hasattr(crypto, "ec_shared_secret")

    assert hasattr(crypto, "hmac_sha256")
    assert hasattr(crypto, "sha256")
