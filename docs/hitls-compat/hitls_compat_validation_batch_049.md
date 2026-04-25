# openHiTLS Compatibility Validation Batch 049

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_add`
- `BN_sub`
- `BN_add_word`
- `BN_sub_word`
- `BN_mul`
- `BN_mul_word`

Status:
- completed

Initial evidence:
- This is the next coherent BN arithmetic-basic cluster without complete `analysis_doc` coverage.
- openHiTLS does have internal arithmetic primitives for this whole family.
- The core question is still public boundary and object-model mismatch, especially `BN_Mul` using internal optimizer instead of public `BN_CTX`.

## 1. `BN_add`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L255), [bn_add.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_add.c#L14)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L485), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L51), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Add()` exists internally, but the BN layer is not installed as public API.

## 2. `BN_sub`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L252), [bn_add.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_add.c#L45)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L513), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L125), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Sub()` exists internally, but the BN layer is not installed as public API.

## 3. `BN_add_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L293), [bn_word.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_word.c#L98)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L499), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L74), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_AddLimb()` exists internally, but the BN layer is not installed as public API and still uses the internal `BN_UINT` model.

## 4. `BN_sub_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L294), [bn_word.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_word.c#L134)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L527), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L147), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_SubLimb()` exists internally, but the BN layer is not installed as public API and still uses the internal `BN_UINT` model.

## 5. `BN_mul`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L256), [bn_mul.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mul.c#L497)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L543), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L216), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Mul()` exists internally, but the BN layer is not installed as public API and the contract uses internal `BN_Optimizer` instead of public `BN_CTX`.

## 6. `BN_mul_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L292), [bn_word.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_word.c#L181)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L557), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L276), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MulLimb()` exists internally, but the BN layer is not installed as public API and still uses the internal `BN_UINT` model.

## Batch 049 summary

Keep `not_available`:
- `BN_add`
- `BN_sub`
- `BN_add_word`
- `BN_sub_word`
- `BN_mul`
- `BN_mul_word`

Main observation:
- The entire arithmetic-basic family exists internally in openHiTLS BN.
- The blocker is still the same:
  - no public installed BN surface
  - low-level contracts depend on internal types such as `BN_UINT` and `BN_Optimizer`
