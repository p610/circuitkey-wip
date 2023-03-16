from circuitkey.schema import CapabiltyCode

# fmt:off
CTAP_INFO = (
    int(2).to_bytes(1, "big"),                    # protocol_version - FIDO2 
    bytes((0x00, 0x01, 0x00)),                    # device_version
    CapabiltyCode.to_byte(                        # capabilities
        CapabiltyCode.WINK, CapabiltyCode.CBOR
    ), 
)

CBOR_INFO = {
    "versions": ["FIDO_2_0"],
    "aaguid": [0x00] * 15 + [0x01],
    "options": {
        "rk": False,                # Specifies whether this authenticator can create discoverable credentials, and therefore can satisfy authenticatorGetAssertion requests with the allowList parameter omitted.
        "up": True,                 # user presence: Indicates that the device is capable of testing user presence.
        "plat": False,              # platform device: Indicates that the device is attached to the client and therefore can’t be removed and used on another client.
        "clientPin": True,          # If present and set to true, it indicates that the device is capable of accepting a PIN from the client and PIN has been set.
    },
    "pinUvAuthProtocols": [1],
    "firmwareVersion": 0x01,
}
# fmt:on
