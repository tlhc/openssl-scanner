# openHiTLS Compatibility Validation Batch 052

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_mod_mul_montgomery`
- `BN_to_montgomery`
- `BN_from_montgomery`
- `BN_mod_exp_mont`
- `BN_mod_exp_mont_consttime`

Status:
- completed

Initial evidence:
- This batch stays on the Montgomery side but focuses on operation APIs rather than context objects.
- openHiTLS has a full internal Montgomery helper layer.
- The deciding factor is still public boundary, not raw functionality.

## 1. `BN_mod_mul_montgomery`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L402), [bn_mont.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mont.c#L26)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1416), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L740), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `MontMulCore()` exists internally, but the BN Montgomery layer is not installed as public API.

## 2. `BN_to_montgomery`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L404), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L948)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1502), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L779), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BnMontEnc()` exists internally, but the BN Montgomery layer is not installed as public API.

## 3. `BN_from_montgomery`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L406), [bn_mont.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mont.c#L162)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1507), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L788), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BnMontDec()` exists internally, but the BN Montgomery layer is not installed as public API.

## 4. `BN_mod_exp_mont`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L307), [bn_exp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_exp.c#L304)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1089), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L298), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MontExp()` exists internally, but the BN Montgomery layer is not installed as public API.

## 5. `BN_mod_exp_mont_consttime`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L309), [bn_exp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_exp.c#L601)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1110), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L305), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MontExpConsttime()` exists internally, but the BN Montgomery layer is not installed as public API.

## Batch 052 summary

Keep `not_available`:
- `BN_mod_mul_montgomery`
- `BN_to_montgomery`
- `BN_from_montgomery`
- `BN_mod_exp_mont`
- `BN_mod_exp_mont_consttime`

Main observation:
- openHiTLS has a capable internal Montgomery operation layer.
- That still does not count for compatibility because the whole layer stays behind the non-public BN API boundary.
