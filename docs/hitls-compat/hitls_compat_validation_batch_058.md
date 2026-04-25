# openHiTLS Compatibility Validation Batch 058

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_GF2m_mod_inv_arr`
- `BN_GF2m_mod_div_arr`
- `BN_GF2m_mod_exp_arr`
- `BN_GF2m_mod_sqrt_arr`
- `BN_GF2m_mod_solve_quad_arr`
- `BN_GF2m_poly2arr`
- `BN_GF2m_arr2poly`

Status:
- completed

Initial evidence:
- This batch closes the GF(2^m) long tail after Batch 056 and Batch 057.
- The same result persists: the corresponding binary-field BN subsystem does not appear in openHiTLS.

## 1. `BN_GF2m_mod_inv_arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L513), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L774)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 2. `BN_GF2m_mod_div_arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L516), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L832)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 3. `BN_GF2m_mod_exp_arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L519), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L860)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 4. `BN_GF2m_mod_sqrt_arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L522), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L938)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 5. `BN_GF2m_mod_solve_quad_arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L525), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L1002)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 6. `BN_GF2m_poly2arr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L527), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L1141)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## 7. `BN_GF2m_arr2poly`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L528), [bn_gf2m.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gf2m.c#L1176)
- openHiTLS evidence: no matching GF(2^m) BN helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no binary-field BN arithmetic family here.

## Batch 058 summary

Keep `not_available`:
- `BN_GF2m_mod_inv_arr`
- `BN_GF2m_mod_div_arr`
- `BN_GF2m_mod_exp_arr`
- `BN_GF2m_mod_sqrt_arr`
- `BN_GF2m_mod_solve_quad_arr`
- `BN_GF2m_poly2arr`
- `BN_GF2m_arr2poly`

Main observation:
- The GF(2^m) result is now complete across both direct and `_arr` helper families.
- The corresponding binary-field BN subsystem does not appear in openHiTLS.
