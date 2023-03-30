## Firmware builder script

This is docker based build script for customized version of circuitpython (with additional user modules).

Currently supported circuitpython ***8.0.3***.

## User modules

### crypto

#### gen_keys

Generates SECP256R1 public, private key pair.

```
import crypto

pub_key, priv_key = crypto.gen_keys()

x, y = pub_key      # byte arrays of x and y coordiantes
priv_keys           # byte array
```

#### shared_secret

Generates shared secret using ECDH.

```
import crypto

x = bytes([1] * 32)
y = bytes([1] * 32)
private_key = bytes([1]*32)

shared_secret = crypto.shared_secret(x, y, private_key)
```

