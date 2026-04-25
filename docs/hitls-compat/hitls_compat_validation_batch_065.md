# openHiTLS Compatibility Validation Batch 065

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_exp`
- `BN_sqr`
- `BN_gcd`
- `BN_div_recp`
- `BN_reciprocal`
- `BN_kronecker`
- `BN_uadd`
- `BN_usub`
- `BN_mask_bits`
- `BN_zero_ex`
- `BN_num_bits_word`
- `BN_secure_new`
- `BN_get_params`
- `BN_set_params`

Status:
- completed

Initial evidence:
- This batch groups arithmetic/support helpers that are adjacent in the BN stack.
- Some have internal-only analogues, while others have no analogue at all.

## 1. `BN_exp`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L303), [bn_exp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_exp.c#L49)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L704), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1089)
- Verdict: keep `not_available`
- Why: openHiTLS only exposes internal modular exponentiation, not a non-modular `BN_exp()` helper.

## 2. `BN_sqr`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L257), [bn_sqr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_sqr.c#L17)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L572), [bn_operation.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_operation.c#L308), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Sqr()` exists internally, but the BN layer is not public and depends on internal `BN_Optimizer`.

## 3. `BN_gcd`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L343), [bn_gcd.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_gcd.c#L549)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L441), [bn_gcd.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_gcd.c#L77), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Gcd()` exists internally, but the BN layer is not public.

## 4. `BN_div_recp`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L457), [bn_recp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_recp.c#L84)
- openHiTLS evidence: no reciprocal-context family exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no reciprocal helper family here.

## 5. `BN_reciprocal`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L330), [bn_recp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_recp.c#L174)
- openHiTLS evidence: no reciprocal helper exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no reciprocal helper family here.

## 6. `BN_kronecker`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L344), [bn_kron.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_kron.c#L17)
- openHiTLS evidence: no Kronecker/Jacobi helper exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no Kronecker/Jacobi helper family here.

## 7. `BN_uadd`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L254), [bn_add.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_add.c#L76)
- openHiTLS internal implementation: [bn_ucal.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_ucal.c#L71), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `UAdd()` exists only in private `bn_ucal` helpers and is not part of installed public headers.

## 8. `BN_usub`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L253), [bn_add.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_add.c#L125)
- openHiTLS internal implementation: [bn_ucal.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_ucal.c#L25), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `USub()` exists only in private `bn_ucal` helpers and is not part of installed public headers.

## 9. `BN_mask_bits`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L325), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L740)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L401), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L368), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MaskBit()` exists internally, but the BN layer is not public.

## 10. `BN_zero_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L199), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L911)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L309), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L261), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Zeroize()` exists internally, but the BN layer is not public.

## 11. `BN_num_bits_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L236), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L100)
- openHiTLS evidence: no matching helper exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no `BN_num_bits_word()`-style helper.

## 12. `BN_secure_new`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L239), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L256)
- openHiTLS evidence: no secure BN allocator exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no `BN_secure_new()`-style secure BN allocator.

## 13. `BN_get_params`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L447), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L67)
- openHiTLS evidence: no BN tuning getter exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no BN tuning-parameter getter.

## 14. `BN_set_params`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L445), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L39)
- openHiTLS evidence: no BN tuning setter exposed in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no BN tuning-parameter setter.

## Batch 065 summary

Keep `not_available`:
- `BN_exp`
- `BN_sqr`
- `BN_gcd`
- `BN_div_recp`
- `BN_reciprocal`
- `BN_kronecker`
- `BN_uadd`
- `BN_usub`
- `BN_mask_bits`
- `BN_zero_ex`
- `BN_num_bits_word`
- `BN_secure_new`
- `BN_get_params`
- `BN_set_params`

Main observation:
- This batch mixes internal-only analogues with complete absences.
- Either way, none of the helpers escape the non-public BN boundary.
