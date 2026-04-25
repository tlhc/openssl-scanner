# openHiTLS Compatibility Validation Batch 060

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_get_rfc2409_prime_768`
- `BN_get_rfc2409_prime_1024`
- `BN_get_rfc3526_prime_1536`
- `BN_get_rfc3526_prime_2048`
- `BN_get_rfc3526_prime_3072`
- `BN_get_rfc3526_prime_4096`

Status:
- completed

Initial evidence:
- This batch starts the constant-prime helper family.
- openHiTLS has an internal `BN_GetRfcConstPrime()` helper, but it is still inside the non-public BN layer.

## 1. `BN_get_rfc2409_prime_768`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L555), [bn_const.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_const.c#L25)
- openHiTLS internal evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1385), [bn_const.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_const.c#L353), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: internal `BN_GetRfcConstPrime()` starts at RFC2409 1024 and exposes no 768-bit helper.

## 2. `BN_get_rfc2409_prime_1024`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L556), [bn_const.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_const.c#L53)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1385), [bn_const.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_const.c#L353), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GetRfcConstPrime()` can return the 1024-bit group internally, but the BN layer is not public.

## 3. `BN_get_rfc3526_prime_1536`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L559), [bn_const.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_const.c#L85)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1385), [bn_const.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_const.c#L358), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GetRfcConstPrime()` can return the 1536-bit group internally, but the BN layer is not public.

## 4. `BN_get_rfc3526_prime_2048`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L560), [bn_const.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_const.c#L98)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1385), [bn_const.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_const.c#L360), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GetRfcConstPrime()` can return the 2048-bit group internally, but the BN layer is not public.

## 5. `BN_get_rfc3526_prime_3072`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L561), [bn_const.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_const.c#L111)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1385), [bn_const.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_const.c#L362), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GetRfcConstPrime()` can return the 3072-bit group internally, but the BN layer is not public.

## 6. `BN_get_rfc3526_prime_4096`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L562), [bn_const.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_const.c#L124)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1385), [bn_const.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_const.c#L364), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GetRfcConstPrime()` can return the 4096-bit group internally, but the BN layer is not public.

## Batch 060 summary

Keep `not_available`:
- `BN_get_rfc2409_prime_768`
- `BN_get_rfc2409_prime_1024`
- `BN_get_rfc3526_prime_1536`
- `BN_get_rfc3526_prime_2048`
- `BN_get_rfc3526_prime_3072`
- `BN_get_rfc3526_prime_4096`

Main observation:
- openHiTLS does have some internal RFC prime constants.
- That still does not change compatibility because the helper lives behind the non-public BN layer.
