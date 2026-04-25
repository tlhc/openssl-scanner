# openHiTLS Compatibility Validation Batch 062

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)
- OpenSSL reference docs: <https://docs.openssl.org/3.2/man3/BN_cmp/>

Scope:
- `BN_get0_nist_prime_521`
- `BN_value_one`
- `BN_options`
- `BN_security_bits`
- `BN_are_coprime`
- `BN_abs_is_word`

Status:
- completed

Initial evidence:
- This batch finishes the nearby BN constant/helper long tail after the RFC/NIST prime batches.
- The symbols split into three categories:
  - no analogue at all
  - internal-only analogue
  - one symbol (`BN_are_coprime`) that is newer than the local OpenSSL source snapshot and must be cross-checked against official OpenSSL docs

## 1. `BN_get0_nist_prime_521`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L545), [bn_nist.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_nist.c#L247)
- openHiTLS evidence: no matching NIST constant-prime getter found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no BN constant getter family for this NIST prime.

## 2. `BN_value_one`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L207), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L82)
- openHiTLS evidence: no matching constant-one getter found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no `BN_value_one()`-style constant getter.

## 3. `BN_options`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L208), [bn_print.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_print.c#L56)
- openHiTLS evidence: no matching BN configuration-string helper found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no `BN_options()`-style helper.

## 4. `BN_security_bits`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L237), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L888)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1398), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L437), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_SecBits()` exists internally, but the BN layer is not installed as public API.

## 5. `BN_are_coprime`
- OpenSSL declaration/docs: <https://docs.openssl.org/3.2/man3/BN_cmp/>
- History note from the same doc: the function was added in OpenSSL 3.1, which is why it is absent from the local `openssl-3.0.9` source tree.
- openHiTLS internal evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L441), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L257), [bn_gcd.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_gcd.c#L77), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L225), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has only internal `BN_Gcd()` plus `BN_IsOne()` ingredients. There is no public coprime helper, and the whole BN layer remains non-public.

## 6. `BN_abs_is_word`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L191), [bn_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_lib.c#L918)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L323), [bn_basic.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_basic.c#L274), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_IsLimb()` is the closest internal analogue, but the BN layer is not installed as public API.

## Batch 062 summary

Keep `not_available`:
- `BN_get0_nist_prime_521`
- `BN_value_one`
- `BN_options`
- `BN_security_bits`
- `BN_are_coprime`
- `BN_abs_is_word`

Main observation:
- This batch closes another mixed family:
  - `BN_security_bits` and `BN_abs_is_word` have internal-only analogues
  - `BN_value_one`, `BN_options`, and `BN_get0_nist_prime_521` have no matching getter/helper surface
  - `BN_are_coprime` is newer on the OpenSSL side, but still has no public openHiTLS counterpart
