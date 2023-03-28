## Firmware builder script

This is docker based build script for customized version of circuitpython (with additional user modules).

Currently supported circuitpython ***8.1.0***.

## User modules

### crypto

#### ecdsakeys

Generates SECP256R1 public, private key pair.

```
import crypto

pub_key, priv_key = crypto.ecdakeys()

x, y = pub_key      # byte array of x and y coordiantes
priv_keys           # byte array
```

#### sharedsecret

Generates shared secret using ECDH.

```
import crypto

x = bytes([1] * 32)
y = bytes([1] * 32)
private_key = bytes([1]*32)

shared_secret = crypto.sharedsecret(x, y, private_key)
```

