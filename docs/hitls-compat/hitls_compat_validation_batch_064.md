# openHiTLS Compatibility Validation Batch 064

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_mod_add`
- `BN_mod_add_quick`
- `BN_mod_sub`
- `BN_mod_sub_quick`
- `BN_mod_mul`
- `BN_mod_sqr`
- `BN_mod_inverse`
- `BN_mod_lshift`
- `BN_mod_lshift1`
- `BN_mod_lshift1_quick`
- `BN_mod_lshift_quick`

Status:
- completed

Initial evidence:
- This batch groups modular arithmetic helpers.
- openHiTLS has broad internal coverage for this family.
- The blocking issue remains public boundary, plus narrower contracts for the quick variants.

## 1. `BN_mod_add`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L273), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L28)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L626), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L650), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModAdd()` exists internally, but the BN layer is not public.

## 2. `BN_mod_add_quick`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L275), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L99)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1281), [bn_nistmod.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_nistmod.c#L853), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModAddQuick()` exists only in the optimized NIST/ECC path and the BN layer is not public.

## 3. `BN_mod_sub`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L277), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L110)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L645), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L621), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModSub()` exists internally, but the BN layer is not public.

## 4. `BN_mod_sub_quick`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L279), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L186)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1258), [bn_nistmod.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_nistmod.c#L872), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModSubQuick()` exists only in the optimized NIST/ECC path and the BN layer is not public.

## 5. `BN_mod_mul`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L281), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L197)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L665), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L679), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModMul()` exists internally, but the BN layer is not public.

## 6. `BN_mod_sqr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L283), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L226)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L684), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L707), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModSqr()` exists internally, but the BN layer is not public.

## 7. `BN_mod_inverse`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L347), [bn_gcd.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gcd.c#L515)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L458), [bn_gcd.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_gcd.c#L216), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModInv()` exists internally, but the BN layer is not public.

## 8. `BN_mod_lshift`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L286), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L256)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L723), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1150)
- Verdict: keep `not_available`
- Why: only internal `BN_Lshift()` + `BN_Mod()` building blocks exist, not a dedicated public helper.

## 9. `BN_mod_lshift1`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L284), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L234)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L723), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1150)
- Verdict: keep `not_available`
- Why: only internal `BN_Lshift()` + `BN_Mod()` building blocks exist, not a dedicated public helper.

## 10. `BN_mod_lshift1_quick`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L285), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L246)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L723), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1150)
- Verdict: keep `not_available`
- Why: only internal `BN_Lshift()` + `BN_Mod()` building blocks exist, not a dedicated public helper.

## 11. `BN_mod_lshift_quick`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L288), [bn_mod.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mod.c#L283)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L723), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1150)
- Verdict: keep `not_available`
- Why: only internal `BN_Lshift()` + `BN_Mod()` building blocks exist, not a dedicated public helper.

## Batch 064 summary

Keep `not_available`:
- `BN_mod_add`
- `BN_mod_add_quick`
- `BN_mod_sub`
- `BN_mod_sub_quick`
- `BN_mod_mul`
- `BN_mod_sqr`
- `BN_mod_inverse`
- `BN_mod_lshift`
- `BN_mod_lshift1`
- `BN_mod_lshift1_quick`
- `BN_mod_lshift_quick`

Main observation:
- openHiTLS internally covers most modular arithmetic primitives.
- Quick variants are even narrower than OpenSSL and still hidden behind the non-public BN layer.
