# openHiTLS Compatibility Validation Batch 059

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_X931_generate_prime_ex`
- `BN_X931_generate_Xpq`
- `BN_X931_derive_prime_ex`

Status:
- completed

Initial evidence:
- This batch covers the X9.31 prime-generation helpers.
- In openHiTLS sources, no corresponding X9.31 BN helper family appears.

## 1. `BN_X931_generate_prime_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L396), [bn_x931p.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_x931p.c#L219)
- openHiTLS evidence: no matching X9.31 BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no X9.31 BN helper family here.

## 2. `BN_X931_generate_Xpq`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L388), [bn_x931p.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_x931p.c#L162)
- openHiTLS evidence: no matching X9.31 BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no X9.31 BN helper family here.

## 3. `BN_X931_derive_prime_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L391), [bn_x931p.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_x931p.c#L53)
- openHiTLS evidence: no matching X9.31 BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no X9.31 BN helper family here.

## Batch 059 summary

Keep `not_available`:
- `BN_X931_generate_prime_ex`
- `BN_X931_generate_Xpq`
- `BN_X931_derive_prime_ex`

Main observation:
- Unlike many other BN families, this one does not even show an internal-only analogue in openHiTLS.
