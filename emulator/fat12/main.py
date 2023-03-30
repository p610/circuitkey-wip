import crypto
import json

"""
Let's generate a public/private key pairs and a shared secret
to verify that the crypto module is working as expected.
"""

a_public, a_private = crypto.gen_keys()
a_x, a_y = a_public

b_public, b_private = crypto.gen_keys()
b_x, b_y = b_public

shared_1 = crypto.shared_secret(a_x, a_y, b_private)
shared_2 = crypto.shared_secret(b_x, b_y, a_private)

assert shared_1 == shared_2, "Shared secrets don't match"

data = {
    "public": {
        "x": int.from_bytes(a_x, "big"),
        "y": int.from_bytes(a_y, "big"),
    },
    "private": int.from_bytes(a_private, "big"),
    "shared": int.from_bytes(shared_1, "big"),
}

print(json.dumps(data))
