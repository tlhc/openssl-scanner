# openHiTLS Compatibility Validation Batch 053

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_MONT_CTX_set_locked`
- `BN_RECP_CTX_set`
- `BN_mod_exp_recp`
- `BN_mod_exp_mont_word`
- `BN_mod_exp2_mont`
- `BN_mod_exp_mont_consttime_x2`

Status:
- completed

Initial evidence:
- This batch finishes the nearby Montgomery/reciprocal long tail.
- The key checks are whether any reciprocal-context analogue exists at all and whether specialized Montgomery exponentiation helpers have internal-only counterparts.

## 1. `BN_MONT_CTX_set_locked`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L411), [bn_mont.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mont.c#L428)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1068), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L346), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has no lock-protected lazy-init helper analogous to `BN_MONT_CTX_set_locked()`.

## 2. `BN_RECP_CTX_set`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L452), [bn_recp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_recp.c#L45)
- openHiTLS evidence: no reciprocal-context object found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no reciprocal-context object family at all.

## 3. `BN_mod_exp_recp`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L455), [bn_exp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_exp.c#L169)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1089), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L298), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has no reciprocal-context algorithm family; generic Montgomery/internal mod-exp helpers do not provide a reciprocal-specific API surface.

## 4. `BN_mod_exp_mont_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L312), [bn_exp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_exp.c#L1155)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1089), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L298), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS exposes internal `BN_MontExp()`, but no word-base Montgomery exponentiation helper.

## 5. `BN_mod_exp2_mont`
- OpenSSL declaration/implementation: [bn_exp2.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_exp2.c#L16)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1153), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L692), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MontExpMul()` is the closest internal analogue, but the Montgomery layer is not public.

## 6. `BN_mod_exp_mont_consttime_x2`
- OpenSSL declaration/implementation: [bn_exp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_exp.c#L1429)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1153), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L692), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MontExpMul()` is the closest internal analogue, but it is not public and does not match OpenSSL x2 semantics across two potentially different moduli.

## Batch 053 summary

Keep `not_available`:
- `BN_MONT_CTX_set_locked`
- `BN_RECP_CTX_set`
- `BN_mod_exp_recp`
- `BN_mod_exp_mont_word`
- `BN_mod_exp2_mont`
- `BN_mod_exp_mont_consttime_x2`

Main observation:
- This batch closes the nearby reciprocal/Montgomery long tail with the same result:
  - some specialized Montgomery helpers exist internally
  - reciprocal-context APIs do not
  - none of this is a public installed BN surface
