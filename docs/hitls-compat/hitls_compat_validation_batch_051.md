# openHiTLS Compatibility Validation Batch 051

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_MONT_CTX_new`
- `BN_MONT_CTX_free`
- `BN_MONT_CTX_set`
- `BN_MONT_CTX_copy`
- `BN_RECP_CTX_new`
- `BN_RECP_CTX_free`

Status:
- completed

Initial evidence:
- This batch moves from raw BN operations to BN helper context objects.
- The likely question is whether openHiTLS exposes any public Montgomery or reciprocal context surface, or only internal helper objects.

## 1. `BN_MONT_CTX_new`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L401), [bn_mont.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mont.c#L228)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1068), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L346), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MontCreate()` is the closest internal analogue, but the BN Montgomery layer is not public and creation requires a modulus immediately.

## 2. `BN_MONT_CTX_free`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L408), [bn_mont.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mont.c#L252)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1121), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L319), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MontDestroy()` is internal only; the Montgomery helper layer is not public.

## 3. `BN_MONT_CTX_set`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L409), [bn_mont.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mont.c#L263)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1068), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L346), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_MontCreate(mod)` is the nearest internal analogue, but it does not expose OpenSSL `BN_MONT_CTX_set()` mutation semantics on a public object.

## 4. `BN_MONT_CTX_copy`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L410), [bn_mont.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_mont.c#L411)
- openHiTLS evidence: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1068), [bn_mont.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_mont.c#L346), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has an internal Montgomery object, but no copy helper analogous to `BN_MONT_CTX_copy()`, and the whole layer is not public.

## 5. `BN_RECP_CTX_new`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L450), [bn_recp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_recp.c#L20)
- openHiTLS evidence: no matching reciprocal-context object found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: openHiTLS exposes no reciprocal-context object surface at all.

## 6. `BN_RECP_CTX_free`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L451), [bn_recp.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_recp.c#L35)
- openHiTLS evidence: no matching reciprocal-context object found in `crypt_bn.h` or `crypto/bn/src`
- Verdict: keep `not_available`
- Why: same object-model gap as `BN_RECP_CTX_new`; openHiTLS exposes no reciprocal-context object surface at all.

## Batch 051 summary

Keep `not_available`:
- `BN_MONT_CTX_new`
- `BN_MONT_CTX_free`
- `BN_MONT_CTX_set`
- `BN_MONT_CTX_copy`
- `BN_RECP_CTX_new`
- `BN_RECP_CTX_free`

Main observation:
- openHiTLS does have an internal Montgomery helper object, but not a public one.
- Reciprocal-context support does not appear as an exposed object family at all.
