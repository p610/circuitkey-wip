import random

# Channel ID 0 is reserved and 0xffffffff is reserved for broadcast commands,
generate_cid = lambda: random.randint(0 + 1, 0xFFFFFFFF - 1).to_bytes(4, "big")
