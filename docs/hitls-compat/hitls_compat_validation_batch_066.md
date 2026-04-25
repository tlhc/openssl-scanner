# openHiTLS Compatibility Validation Batch 066

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_generate_dsa_nonce`
- `BN_is_prime_fasttest`
- `BN_is_prime_fasttest_ex`
- `BN_priv_rand_range`
- `BN_priv_rand_range_ex`
- `BN_pseudo_rand`
- `BN_pseudo_rand_range`
- `BN_signed_bin2bn`
- `BN_signed_bn2bin`
- `BN_signed_bn2lebin`
- `BN_signed_bn2native`
- `BN_signed_lebin2bn`
- `BN_signed_native2bn`

Status:
- completed

Initial evidence:
- This batch mixes deprecated random/primality helpers with signed-binary conversion helpers.
- openHiTLS either has only internal-only random analogues or no signed-binary helper family at all.

## 1. `BN_generate_dsa_nonce`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L550), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L251)
- openHiTLS evidence: no matching helper exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no DSA-nonce BN helper.

## 2. `BN_is_prime_fasttest`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L366), [bn_depr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_depr.c#L55)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L781), [bn_prime.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_prime.c#L428), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_PrimeCheck()` exists internally, but there is no fasttest-specific public helper.

## 3. `BN_is_prime_fasttest_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L375), [bn_prime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_prime.c#L236)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L781), [bn_prime.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_prime.c#L428), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_PrimeCheck()` exists internally, but there is no fasttest-specific public helper.

## 4. `BN_priv_rand_range`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L228), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L225)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L846), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L863), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L143), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L148), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: internal range-random helpers exist, but the BN layer is not public and there is no OpenSSL-style private/public separation.

## 5. `BN_priv_rand_range_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L226), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L218)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L863), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L148), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: internal range-random helpers exist, but the BN layer is not public and there is no OpenSSL-style private/public separation or strength contract.

## 6. `BN_pseudo_rand`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L231), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L231)
- openHiTLS evidence: no matching pseudo-random helper exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no deprecated pseudo-random BN helper.

## 7. `BN_pseudo_rand_range`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L233), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L236)
- openHiTLS evidence: no matching pseudo-random range helper exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no deprecated pseudo-random BN range helper.

## 8-13. Signed-binary helpers
- OpenSSL declarations: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L578), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L579), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L580), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L581), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L582), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L583)
- openHiTLS evidence: no matching signed binary conversion family exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no signed-binary BN conversion family.

## Batch 066 summary

Keep `not_available`:
- `BN_generate_dsa_nonce`
- `BN_is_prime_fasttest`
- `BN_is_prime_fasttest_ex`
- `BN_priv_rand_range`
- `BN_priv_rand_range_ex`
- `BN_pseudo_rand`
- `BN_pseudo_rand_range`
- `BN_signed_bin2bn`
- `BN_signed_bn2bin`
- `BN_signed_bn2lebin`
- `BN_signed_bn2native`
- `BN_signed_lebin2bn`
- `BN_signed_native2bn`

Main observation:
- The random side has only internal-only analogues at best.
- The signed-binary conversion side has no corresponding family at all.
