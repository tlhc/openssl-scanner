# openHiTLS Compatibility Validation Batch 055

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_generate_prime`
- `BN_generate_prime_ex`
- `BN_generate_prime_ex2`
- `BN_check_prime`
- `BN_is_prime`
- `BN_is_prime_ex`

Status:
- completed

Initial evidence:
- This batch focuses on BN prime-generation and primality-check helpers.
- openHiTLS has an internal prime/check subsystem.
- The deciding factor is still whether that subsystem is public and whether its callback/context contracts match OpenSSL.

## 1. `BN_generate_prime`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L357), [bn_depr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_depr.c#L22)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L762), [bn_prime.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_prime.c#L516), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GenPrime()` exists internally, but the BN layer is not installed as public API.

## 2. `BN_generate_prime_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L382), [bn_prime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_prime.c#L213)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L762), [bn_prime.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_prime.c#L516), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GenPrime()` exists internally, but the BN layer is not installed as public API and its parameter contract does not match OpenSSL `BN_generate_prime_ex()`.

## 3. `BN_generate_prime_ex2`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L379), [bn_prime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_prime.c#L123)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L762), [bn_prime.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_prime.c#L516), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GenPrime()` exists internally, but the BN layer is not installed as public API and its parameter contract does not match OpenSSL `BN_generate_prime_ex2()`.

## 4. `BN_check_prime`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L384), [bn_prime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_prime.c#L255)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L781), [bn_prime.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_prime.c#L428), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_PrimeCheck()` exists internally, but the BN layer is not installed as public API and still depends on internal `BN_Optimizer` and `BN_CbCtx`.

## 5. `BN_is_prime`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L362), [bn_depr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_depr.c#L46)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L781), [bn_prime.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_prime.c#L428), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_PrimeCheck()` exists internally, but the BN layer is not installed as public API and its parameter contract does not match deprecated OpenSSL `BN_is_prime()`.

## 6. `BN_is_prime_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L373), [bn_prime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_prime.c#L230)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L781), [bn_prime.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_prime.c#L428), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_PrimeCheck()` exists internally, but the BN layer is not installed as public API and still depends on internal `BN_Optimizer` and `BN_CbCtx`.

## Batch 055 summary

Keep `not_available`:
- `BN_generate_prime`
- `BN_generate_prime_ex`
- `BN_generate_prime_ex2`
- `BN_check_prime`
- `BN_is_prime`
- `BN_is_prime_ex`

Main observation:
- openHiTLS internally implements prime generation and primality testing.
- That still does not raise compatibility because the BN layer is not public and the callback/context contracts stay internal.
