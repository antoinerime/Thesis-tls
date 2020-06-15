This repository contains the extended version of picotls to execute plugins and the code used to gather the dataset.

More info about the dataset can be found in the dataset directory

picotls
===

The TLS protocol ipmlementation of picotls is licensed under the MIT license.

License and the cryptographic algorithms supported by the crypto bindings are as follows:

| Binding | License | Key Exchange | Certificate | AEAD cipher |
|:-----:|:-----:|:-----:|:-----:|:-----:|
| minicrypto | [CC0](https://github.com/ctz/cifra/) / [2-clause BSD](https://github.com/kmackay/micro-ecc) | secp256r1, x25519 | ECDSA (P256)<sup>1</sup> | AES-128-GCM, chacha20-poly1305 |
| OpenSSL | OpenSSL | secp256r1, secp384r1, secp521r1, x25519 | RSA, ECDSA (P256) | AES-128-GCM, chacha20-poly1305 |

Note 1: Minicrypto binding is capable of signing a handshake using the certificate's key, but cannot verify a signature sent by the peer.

Building picotls
---

If you have cloned picotls from git then ensure that you have initialised the submodules:
```
% git submodule init
% git submodule update
```
Before using the uBPF virtual machine, you must build it. Go to the uBPF directory for more informations

Build using cmake:
```
% cmake .
% make
% make check
```

Developer documentation
---

Developer documentation should be available on [the wiki](https://github.com/h2o/picotls/wiki).

Using the cli command
---

Run the test server (at 127.0.0.1:8443):
```
% ./cli -c /path/to/certificate.pem -k /path/to/private-key.pem  127.0.0.1 8443
```
Using a plugin:
```
% ./cli -c /path/to/certificate.pem -k /path/to/private-key.pem -p /path/to/manifest.plugin  127.0.0.1 8443
```

Connect to the test server:
```
% ./cli 127.0.0.1 8443
```

Using resumption:
```
% ./cli -s session-file 127.0.0.1 8443
```
The session-file is read-write.
The cli server implements a single-entry session cache.
The cli server sends NewSessionTicket when it first sends application data after receiving ClientFinished.

Using early-data:
```
% ./cli -s session-file -e 127.0.0.1 8443
```
When `-e` option is used, client first waits for user input, and then sends CLIENT_HELLO along with the early-data.

License
---

The software is provided under the MIT license.
Note that additional licences apply if you use the minicrypto binding (see above).
