# openHiTLS Compatibility Validation Batch 044

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_copy`
- `BN_dup`
- `BN_get_word`
- `BN_set_word`
- `BN_swap`
- `BN_with_flags`

Status:
- completed

Initial evidence:
- This is the next coherent BN value/copy cluster without complete `analysis_doc` coverage.
- These interfaces are all low-level BigNum object helpers.
- The main check is whether openHiTLS exposes any public replacement at all, or only internal BN helpers hidden under `crypto/bn/include`.

## 1. `BN_copy`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L241), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L336)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L218), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L184), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Copy()` exists internally, but the BN layer is not installed as public API.

## 2. `BN_dup`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L334), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L317)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L229), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L202), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Dup()` exists internally, but the BN layer is not installed as public API.

## 3. `BN_get_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L296), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L410)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L348), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L301), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GetLimb()` exists internally and is close functionally, but the BN layer is not public and still uses the internal `BN_UINT` model.

## 4. `BN_set_word`
- Existing truth entry: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- Prior evidence already landed in [hitls_compat_validation_batch_005.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_005.md)
- Verdict: keep `not_available`
- Why: this batch re-validates the existing Batch 005 conclusion: internal `BN_SetLimb()` exists, but the BN layer is not public and still uses the internal `BN_UINT` model.

## 5. `BN_swap`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L242), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L365)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L218), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L229)
- Verdict: keep `not_available`
- Why: openHiTLS internal BN support exposes copy/dup helpers, but no swap helper and no public BN object API.

## 6. `BN_with_flags`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L94), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L954)
- openHiTLS internal declaration/evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L205), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L297), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has internal flag mutators/checkers (`BN_SetFlag` / `BN_IsFlag`), but no `BN_with_flags()`-style alias/view helper, and the BN layer is not public.

## Batch 044 summary

Keep `not_available`:
- `BN_copy`
- `BN_dup`
- `BN_get_word`
- `BN_set_word`
- `BN_swap`
- `BN_with_flags`

Main observation:
- This batch reinforces the same BN rule already settled in earlier batches:
  - internal helpers often exist
  - they do not count toward compatibility unless they are part of the public installed surface
- `BN_swap` and `BN_with_flags` are stricter still:
  - there is no direct openHiTLS analogue even in the internal BN helper set
