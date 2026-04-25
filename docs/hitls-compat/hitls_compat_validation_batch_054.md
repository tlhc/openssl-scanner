# openHiTLS Compatibility Validation Batch 054

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_div`
- `BN_div_word`
- `BN_mod`
- `BN_mod_word`
- `BN_nnmod`
- `BN_mod_mul_reciprocal`

Status:
- completed

Initial evidence:
- This batch shifts from Montgomery helpers to general division/modulus helpers.
- openHiTLS likely has several internal arithmetic analogues here, but reciprocal-specific APIs may still be absent.

## 1. `BN_div`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L269), [bn_div.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_div.c#L209)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L591), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L399), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Div()` exists internally, but the BN layer is not installed as public API and depends on internal `BN_Optimizer`.

## 2. `BN_div_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L291), [bn_word.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_word.c#L61)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L607), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L467), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_DivLimb()` exists internally, but the BN layer is not installed as public API and uses the internal `BN_UINT` model.

## 3. `BN_mod`
- OpenSSL declaration/evidence: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L271)
- Verdict: current truth-library keyset has no standalone `BN_mod` entry because OpenSSL exposes it as a macro over `BN_div`.
- Why: this batch records the evidence in the doc, but does not expand the JSON keyset.

## 4. `BN_mod_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L290), [bn_word.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_word.c#L13)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L739), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L574), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModLimb()` exists internally, but the BN layer is not installed as public API and uses the internal `BN_UINT` model.

## 5. `BN_nnmod`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L272), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L13)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L723), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L523), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Mod()` exists internally, but there is no separate nnmod-specific public helper and the BN layer is not public.

## 6. `BN_mod_mul_reciprocal`
- OpenSSL declaration/implementation: [bn_recp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_recp.c#L55)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L665), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L679), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has internal generic `BN_ModMul()`, but no reciprocal-context algorithm family and no reciprocal-specific API surface.

## Batch 054 summary

Keep `not_available`:
- `BN_div`
- `BN_div_word`
- `BN_mod_word`
- `BN_nnmod`
- `BN_mod_mul_reciprocal`

Out-of-band note:
- `BN_mod` is an OpenSSL macro, not a standalone entry in the current truth-library keyset. This batch records its evidence in the doc without expanding the JSON mapping.

Main observation:
- openHiTLS internally covers most generic division/modulus primitives.
- That still does not change compatibility because the BN layer is not public, and reciprocal-specific APIs remain absent.
