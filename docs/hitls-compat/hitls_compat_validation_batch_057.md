# openHiTLS Compatibility Validation Batch 057

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_GF2m_mod_div`
- `BN_GF2m_mod_exp`
- `BN_GF2m_mod_solve_quad`
- `BN_GF2m_mod_arr`
- `BN_GF2m_mod_mul_arr`
- `BN_GF2m_mod_sqr_arr`

Status:
- completed

Initial evidence:
- This batch continues the GF(2^m) family after Batch 056.
- If the first batch result holds, these interfaces are likely to remain absent because the corresponding binary-field BN subsystem does not appear in openHiTLS.

## 1. `BN_GF2m_mod_div`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L486), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L799)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 2. `BN_GF2m_mod_exp`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L489), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L906)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 3. `BN_GF2m_mod_solve_quad`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L495), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L1107)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 4. `BN_GF2m_mod_arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L505), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L292)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 5. `BN_GF2m_mod_mul_arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L507), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L410)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 6. `BN_GF2m_mod_sqr_arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L510), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L494)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## Batch 057 summary

Keep `not_available`:
- `BN_GF2m_mod_div`
- `BN_GF2m_mod_exp`
- `BN_GF2m_mod_solve_quad`
- `BN_GF2m_mod_arr`
- `BN_GF2m_mod_mul_arr`
- `BN_GF2m_mod_sqr_arr`

Main observation:
- Batch 056's conclusion holds without exception.
- The extended GF(2^m) helper family also does not appear in openHiTLS.
