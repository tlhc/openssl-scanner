# openHiTLS Compatibility Validation Batch 047

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_bin2bn`
- `BN_lebin2bn`
- `BN_native2bn`
- `BN_hex2bn`
- `BN_dec2bn`
- `BN_mpi2bn`

Status:
- completed

Initial evidence:
- This is the next coherent BN conversion/parse cluster without complete `analysis_doc` coverage.
- openHiTLS likely has several internal `BN_*2Bn` style helpers, but the public boundary and string/binary contract differences still need to be checked one by one.

## 1. `BN_bin2bn`
- Existing truth entry: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- Prior evidence already landed in [hitls_compat_validation_batch_005.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_005.md)
- Verdict: keep `not_available`
- Why: this batch re-validates the existing Batch 005 conclusion: internal `BN_Bin2Bn()` exists, but the BN layer is not public.

## 2. `BN_lebin2bn`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L246), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L544)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L877)
- Verdict: keep `not_available`
- Why: openHiTLS exposes only internal big-endian `BN_Bin2Bn()` and no little-endian parse helper.

## 3. `BN_native2bn`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L248), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L598)
- openHiTLS evidence: no matching native-endian parse helper found in `crypt_bn.h`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no native-endian BN parse helper.

## 4. `BN_hex2bn`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L340), [bn_conv.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_conv.c#L126)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L944), [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L350), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Hex2Bn()` exists internally, but the BN layer is not installed as public API.

## 5. `BN_dec2bn`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L341), [bn_conv.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_conv.c#L203)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L971), [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L478), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Dec2Bn()` exists internally, but the BN layer is not installed as public API.

## 6. `BN_mpi2bn`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L250), [bn_mpi.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mpi.c#L42)
- openHiTLS evidence: no matching MPI-format parse helper found in `crypt_bn.h`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no MPI-format BN parse helper.

## Batch 047 summary

Keep `not_available`:
- `BN_bin2bn`
- `BN_lebin2bn`
- `BN_native2bn`
- `BN_hex2bn`
- `BN_dec2bn`
- `BN_mpi2bn`

Main observation:
- openHiTLS covers some parse helpers internally (`BN_Bin2Bn`, `BN_Hex2Bn`, `BN_Dec2Bn`), but the BN layer is not public.
- For `lebin/native/mpi`, the gap is wider:
  - there is no direct helper even in the internal BN surface
