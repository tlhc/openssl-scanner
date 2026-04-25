# openHiTLS Compatibility Validation Batch 056

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_GF2m_add`
- `BN_GF2m_mod`
- `BN_GF2m_mod_mul`
- `BN_GF2m_mod_sqr`
- `BN_GF2m_mod_inv`
- `BN_GF2m_mod_sqrt`

Status:
- completed

Initial evidence:
- This batch begins the GF(2^m) arithmetic family.
- OpenSSL exposes a dedicated binary-field BN layer here.
- In the openHiTLS BN tree, no matching GF2m helper family appears in `crypt_bn.h` or `crypto/bn/src`.

## 1. `BN_GF2m_add`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L472), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L252)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 2. `BN_GF2m_mod`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L477), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L390)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 3. `BN_GF2m_mod_mul`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L479), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L465)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 4. `BN_GF2m_mod_sqr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L482), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L529)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 5. `BN_GF2m_mod_inv`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L484), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L733)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 6. `BN_GF2m_mod_sqrt`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L492), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L972)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## Batch 056 summary

Keep `not_available`:
- `BN_GF2m_add`
- `BN_GF2m_mod`
- `BN_GF2m_mod_mul`
- `BN_GF2m_mod_sqr`
- `BN_GF2m_mod_inv`
- `BN_GF2m_mod_sqrt`

Main observation:
- This is stronger than the usual BN result.
- For these GF(2^m) APIs, openHiTLS does not merely hide an internal analogue behind a non-public BN layer.
- The corresponding GF(2^m) helper family does not appear in the openHiTLS BN tree at all.
