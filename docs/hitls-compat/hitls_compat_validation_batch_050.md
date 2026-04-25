# openHiTLS Compatibility Validation Batch 050

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_lshift`
- `BN_lshift1`
- `BN_rshift`
- `BN_rshift1`
- `BN_set_bit`
- `BN_clear_bit`

Status:
- completed

Initial evidence:
- This is the next coherent BN shift/bit-manipulation cluster without complete `analysis_doc` coverage.
- openHiTLS likely has internal shift/bit helpers, but the public boundary and exact low-level contracts still need to be verified.

## 1. `BN_lshift`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L301), [bn_shift.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_shift.c#L81)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1150), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L898), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Lshift()` exists internally, but the BN layer is not installed as public API.

## 2. `BN_lshift1`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L302), [bn_shift.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_shift.c#L14)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1150), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L898), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Lshift()` can approximate a 1-bit shift internally via `n = 1`, but there is no dedicated public `BN_lshift1()` helper and the BN layer is not public.

## 3. `BN_rshift`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L331), [bn_shift.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_shift.c#L150)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1136), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L871), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Rshift()` exists internally, but the BN layer is not installed as public API.

## 4. `BN_rshift1`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L332), [bn_shift.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_shift.c#L45)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1136), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L871), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Rshift()` can approximate a 1-bit shift internally via `n = 1`, but there is no dedicated public `BN_rshift1()` helper and the BN layer is not public.

## 5. `BN_set_bit`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L336), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L685)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L375), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L328), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_SetBit()` exists internally, but the BN layer is not installed as public API.

## 6. `BN_clear_bit`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L337), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L708)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L388), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L347), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ClrBit()` exists internally, but the BN layer is not installed as public API.

## Batch 050 summary

Keep `not_available`:
- `BN_lshift`
- `BN_lshift1`
- `BN_rshift`
- `BN_rshift1`
- `BN_set_bit`
- `BN_clear_bit`

Main observation:
- openHiTLS internally covers this whole shift/bit family.
- The blocker remains unchanged:
  - no public installed BN surface
  - no OpenSSL-compatible low-level BIGNUM API boundary
