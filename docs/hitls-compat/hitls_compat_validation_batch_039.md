# openHiTLS Compatibility Validation Batch 039

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_bn2binpad`
- `BN_cmp`
- `BN_mod_exp`
- `BN_num_bits`

Status:
- completed

Initial evidence:
- This is the next coherent BN-heavy cluster without `analysis_doc`.
- Current scan aggregation shows:
  - `BN_bn2binpad`: 9 repos
  - `BN_cmp`: 9 repos
  - `BN_mod_exp`: 8 repos
  - `BN_num_bits`: 7 repos
- This batch extends the already-established Batch 005 rule:
  - openHiTLS still has internal BN support
  - but the BN layer is not part of the installed public API surface

## 1. `BN_bn2binpad`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L245), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L532)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L929), [bn_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_utils.c#L111), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Bn2BinFixZero` is a real internal analogue for padded big-endian export, but it lives under `crypto/bn/include/` and that tree is not installed. The scanner truth library is keyed to public replacement surfaces, so internal-only BN helpers do not count.

## 2. `BN_cmp`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L298), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L638)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L471), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L31), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS does implement the compare primitive, but only inside the internal BN layer. There is no installed public `BN_Cmp`-style entry point.

## 3. `BN_mod_exp`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L305), [bn_exp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_exp.c#L97)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L704), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L807), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModExp` exists internally, but the entire BigNum object model plus `BN_Optimizer` context remains private to the BN subsystem and is not exported through installed public headers.

## 4. `BN_num_bits`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L235), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L178)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L412), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L393), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Bits` matches the basic computation, but it is still part of the private BN subsystem, not the installed public API.

## Batch 039 summary

Keep `not_available`:
- `BN_bn2binpad`
- `BN_cmp`
- `BN_mod_exp`
- `BN_num_bits`

Main observation:
- openHiTLS does have a fairly complete internal BN implementation.
- For this scanner truth library, internal-only analogues do not upgrade symbol status.
- Availability requires an installed public API surface, not just a same-purpose function somewhere under `crypto/`.
