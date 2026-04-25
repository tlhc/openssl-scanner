# openHiTLS Compatibility Validation Batch 048

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_bn2hex`
- `BN_bn2dec`
- `BN_bn2mpi`
- `BN_print`
- `BN_print_fp`
- `BN_bn2nativepad`

Status:
- completed

Initial evidence:
- This is the next coherent BN export/print cluster without complete `analysis_doc` coverage.
- It should settle whether openHiTLS exposes any public formatting/export helpers or only internal binary conversion primitives.

## 1. `BN_bn2hex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L338), [bn_conv.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_conv.c#L17)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L957), [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L398), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Bn2Hex()` exists internally, but the BN layer is not installed as public API.

## 2. `BN_bn2dec`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L339), [bn_conv.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_conv.c#L52)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L981), [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L602), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Bn2Dec()` exists internally, but the BN layer is not installed as public API.

## 3. `BN_bn2mpi`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L251), [bn_mpi.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mpi.c#L14)
- openHiTLS evidence: no matching MPI-format export helper found in `crypt_bn.h`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no MPI-format BN export helper.

## 4. `BN_print`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L329), [bn_print.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_print.c#L31)
- openHiTLS public/internal evidence: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L456), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L957), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has public UIO write APIs, but no public BN formatter. Internal `BN_Bn2Hex()` alone is not sufficient because the BN layer is not public.

## 5. `BN_print_fp`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L327), [bn_print.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_print.c#L17)
- openHiTLS public/internal evidence: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L301), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L456), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L957), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has FILE-backed UIO support, but no public BN formatter. Internal `BN_Bn2Hex()` alone is not sufficient because the BN layer is not public.

## 6. `BN_bn2nativepad`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L249), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L607)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L892), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L929), [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L76), [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L111), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS exposes internal big-endian export helpers, but no native-endian export helper and no public BN API.

## Batch 048 summary

Keep `not_available`:
- `BN_bn2hex`
- `BN_bn2dec`
- `BN_bn2mpi`
- `BN_print`
- `BN_print_fp`
- `BN_bn2nativepad`

Main observation:
- openHiTLS does have some internal textual export helpers (`BN_Bn2Hex`, `BN_Bn2Dec`).
- That still does not change compatibility because:
  - the BN layer is not public
  - no public BN formatter exists for `UIO`/`FILE` printing paths
  - no MPI/native-endian export helper exists
