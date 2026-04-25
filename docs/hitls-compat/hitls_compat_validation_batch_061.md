# openHiTLS Compatibility Validation Batch 061

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_get_rfc3526_prime_6144`
- `BN_get_rfc3526_prime_8192`
- `BN_get0_nist_prime_192`
- `BN_get0_nist_prime_224`
- `BN_get0_nist_prime_256`
- `BN_get0_nist_prime_384`

Status:
- completed

Initial evidence:
- This batch continues the constant-prime helper family.
- openHiTLS still has internal RFC constant support, but no public BN surface.
- For the NIST constant-prime getters, there is no matching helper surfaced in the openHiTLS BN tree.

## 1. `BN_get_rfc3526_prime_6144`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L563), [bn_const.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_const.c#L137)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1385), [bn_const.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_const.c#L366), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GetRfcConstPrime()` can return the 6144-bit group internally, but the BN layer is not public.

## 2. `BN_get_rfc3526_prime_8192`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L564), [bn_const.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_const.c#L150)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1385), [bn_const.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_const.c#L368), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_GetRfcConstPrime()` can return the 8192-bit group internally, but the BN layer is not public.

## 3. `BN_get0_nist_prime_192`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L541), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L227)
- openHiTLS evidence: no matching NIST constant-prime getter found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no BN constant getter family for these NIST primes.

## 4. `BN_get0_nist_prime_224`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L542), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L232)
- openHiTLS evidence: no matching NIST constant-prime getter found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no BN constant getter family for these NIST primes.

## 5. `BN_get0_nist_prime_256`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L543), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L237)
- openHiTLS evidence: no matching NIST constant-prime getter found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no BN constant getter family for these NIST primes.

## 6. `BN_get0_nist_prime_384`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L544), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L242)
- openHiTLS evidence: no matching NIST constant-prime getter found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no BN constant getter family for these NIST primes.

## Batch 061 summary

Keep `not_available`:
- `BN_get_rfc3526_prime_6144`
- `BN_get_rfc3526_prime_8192`
- `BN_get0_nist_prime_192`
- `BN_get0_nist_prime_224`
- `BN_get0_nist_prime_256`
- `BN_get0_nist_prime_384`

Main observation:
- The RFC constant family still has internal-only support.
- The NIST constant-prime getter family does not appear in openHiTLS at all.
