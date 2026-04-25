# openHiTLS Compatibility Validation Batch 046

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_rand`
- `BN_rand_ex`
- `BN_priv_rand`
- `BN_priv_rand_ex`
- `BN_rand_range`
- `BN_rand_range_ex`

Status:
- completed

Initial evidence:
- This is the next coherent BN random-generation cluster without complete `analysis_doc` coverage.
- openHiTLS appears to have internal `BN_Rand*` helpers, but those need to be checked against public header/export boundaries and private/public RNG semantics.

## 1. `BN_rand`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L219), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L108)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L810), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L80), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_Rand()` exists internally, but the BN layer is not installed as public API.

## 2. `BN_rand_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L217), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L102)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L829), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L85), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_RandEx()` exists internally, but the BN layer is not installed as public API and OpenSSL `strength` semantics are not exposed at the BN API level.

## 3. `BN_priv_rand`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L222), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L126)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L810), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L829), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L80), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L85), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has internal BN random helpers, but no public BN API and no OpenSSL-style private/public BN RNG separation.

## 4. `BN_priv_rand_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L220), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L119)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L829), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L85), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_RandEx()` exists internally, but there is no public BN API and no OpenSSL-style private/public BN RNG separation or `strength` contract.

## 5. `BN_rand_range`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L225), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L212)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L846), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L143), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_RandRange()` exists internally, but the BN layer is not installed as public API.

## 6. `BN_rand_range_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L223), [bn_rand.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_rand.c#L205)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L863), [bn_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_rand.c#L148), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_RandRangeEx()` exists internally, but the BN layer is not installed as public API and OpenSSL `strength` semantics are not exposed at the BN API level.

## Batch 046 summary

Keep `not_available`:
- `BN_rand`
- `BN_rand_ex`
- `BN_priv_rand`
- `BN_priv_rand_ex`
- `BN_rand_range`
- `BN_rand_range_ex`

Main observation:
- openHiTLS does implement a real internal BN random subsystem.
- That still does not raise compatibility status because:
  - the BN layer is not public
  - the OpenSSL `priv/public` and `strength` semantics are not surfaced as BN APIs
