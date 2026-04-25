# openHiTLS Compatibility Validation Batch 041

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_GENCB_call`
- `BN_GENCB_free`
- `BN_GENCB_get_arg`
- `BN_GENCB_new`
- `BN_GENCB_set`
- `BN_GENCB_set_old`

Status:
- completed

Initial evidence:
- This is the next coherent BN callback-management cluster without `analysis_doc`.
- Early OpenSSL evidence shows a dedicated `BN_GENCB` callback object model.
- openHiTLS may have callback-like `BN_CbCtx` pieces internally, but those need to be checked against public header/export boundaries before any status change.

## 1. `BN_GENCB_new`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L99), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L965)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L134), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L94), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_CbCtxCreate()` is a direct internal analogue, but the BN callback layer is not installed as public API.

## 2. `BN_GENCB_free`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L100), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L977)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L178), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L134), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_CbCtxDestroy()` exists internally, but the callback object model is not installed publicly.

## 3. `BN_GENCB_get_arg`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L110), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L1014)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L168), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L114), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_CbCtxGetArg()` is the matching internal accessor, but the callback layer is not part of the installed public surface.

## 4. `BN_GENCB_call`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L97), [bn_prime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_prime.c#L101)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L159), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L122), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_CbCtxCall()` is internal only, and its default return convention is different: OpenSSL returns `1` when no callback is present, while openHiTLS returns `CRYPT_SUCCESS`.

## 5. `BN_GENCB_set`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L107), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L1005)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L146), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L104), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_CbCtxSet()` is the nearest internal setter, but it is not public and there is no OpenSSL-style `BN_GENCB *` callback signature exposed.

## 6. `BN_GENCB_set_old`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L103), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L995)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L146), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L104), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS only has one internal callback setter shape. It does not expose OpenSSL's separate old-style callback mode, and the whole BN callback layer remains non-public.

## Batch 041 summary

Keep `not_available`:
- `BN_GENCB_call`
- `BN_GENCB_free`
- `BN_GENCB_get_arg`
- `BN_GENCB_new`
- `BN_GENCB_set`
- `BN_GENCB_set_old`

Main observation:
- openHiTLS does have an internal BN callback object model: `BN_CbCtx*`.
- That is not enough for the scanner truth library because:
  - `crypto/bn/include/crypt_bn.h` is not installed as public API
  - the callback contracts are not identical to OpenSSL `BN_GENCB*`
