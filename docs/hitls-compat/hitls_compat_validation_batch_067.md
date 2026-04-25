# openHiTLS Compatibility Validation Batch 067

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_asc2bn`
- `BN_bn2lebinpad`
- `BN_bntest_rand`
- `BN_clear`
- `BN_mod_sqrt`
- `BN_nist_mod_192`
- `BN_nist_mod_224`
- `BN_nist_mod_256`
- `BN_nist_mod_384`
- `BN_nist_mod_521`
- `BN_nist_mod_func`
- `BN_to_ASN1_ENUMERATED`
- `BN_to_ASN1_INTEGER`

Status:
- completed

Initial evidence:
- This batch is the BN tail-end cleanup batch.
- It mixes a few internal-only analogues (`BN_clear`, `BN_mod_sqrt`) with families that have no matching public surface at all.

## 1. `BN_asc2bn`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L342), [bn_conv.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_conv.c#L273)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L944), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L971)
- Verdict: keep `not_available`
- Why: openHiTLS exposes internal `BN_Hex2Bn()` and `BN_Dec2Bn()`, but no `BN_asc2bn()`-style wrapper and the BN layer is not public.

## 2. `BN_bn2lebinpad`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L247), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L591)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L892), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L929)
- Verdict: keep `not_available`
- Why: openHiTLS exposes only internal big-endian `BN_Bn2Bin()` / `BN_Bn2BinFixZero()`, not a little-endian pad helper.

## 3. `BN_bntest_rand`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L577), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L113)
- openHiTLS evidence: no matching testing-only BN random helper exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no `BN_bntest_rand()`-style test helper.

## 4. `BN_clear`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L333), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L398)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L309), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L261), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Zeroize()` is the closest internal analogue, but the BN layer is not public.

## 5. `BN_mod_sqrt`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L349), [bn_sqrt.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_sqrt.c#L13)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1179), [bn_sqrt.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_sqrt.c#L298), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_ModSqrt()` exists internally, but the BN layer is not public.

## 6-10. `BN_nist_mod_*`
- OpenSSL declarations/implementations: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L535), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L536), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L537), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L538), [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L539), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L329), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L465), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L637), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L874), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L1134)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1304), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1326), [bn_nistmod.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_nistmod.c#L314), [bn_nistmod.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_nistmod.c#L355), [bn_nistmod.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_nistmod.c#L482), [bn_nistmod.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_nistmod.c#L578), [bn_nistmod.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_nistmod.c#L753)
- Verdict: keep `not_available`
- Why: openHiTLS has internal NIST reduction helpers, but no public `BN_nist_mod_*` family.

## 11. `BN_nist_mod_func`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L547), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L1202)
- openHiTLS evidence: no `BN_nist_mod_func()`-style selector exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public function-pointer selector for NIST reductions.

## 12-13. ASN.1 conversion helpers
- OpenSSL declarations: [bn.h](openssl-3.0.9/include/openssl/bn.h:691), [bn.h](openssl-3.0.9/include/openssl/bn.h:689)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1_internal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/include/bsl_asn1_internal.h#L97)
- Verdict: keep `not_available`
- Why: openHiTLS exposes generic ASN.1 limb encoding, but no `BN_to_ASN1_INTEGER()` / `BN_to_ASN1_ENUMERATED()` object helpers.

## Batch 067 summary

Keep `not_available`:
- `BN_asc2bn`
- `BN_bn2lebinpad`
- `BN_bntest_rand`
- `BN_clear`
- `BN_mod_sqrt`
- `BN_nist_mod_192`
- `BN_nist_mod_224`
- `BN_nist_mod_256`
- `BN_nist_mod_384`
- `BN_nist_mod_521`
- `BN_nist_mod_func`
- `BN_to_ASN1_ENUMERATED`
- `BN_to_ASN1_INTEGER`

Main observation:
- This batch closes the remaining BN tail.
- The last few items either stay behind the non-public BN layer or have no corresponding public surface at all.
