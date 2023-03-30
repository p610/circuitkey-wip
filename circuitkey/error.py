from circuitkey.schema import Error


class CtapError(Exception):
    def __init__(self, code: Error, msg: str):
        assert Error.is_ctap_error(code), "Error code %d is not a CTAP error" % code

        self.code = code
        self.msg = msg

    def __str__(self):
        return "CTAP error {}: {}".format(hex(self.code), self.msg)


class CborError(Exception):
    def __init__(self, code: Error, msg: str):
        self.code = code
        self.msg = msg

    def __str__(self):
        return "CBOR error {}: {}".format(hex(self.code), self.msg)


class AbortError(Exception):
    def __init__(self, cid, nonce):
        self.cid = cid
        self.nonce = nonce
