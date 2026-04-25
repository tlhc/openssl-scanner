# openHiTLS Compatibility Validation Batch 040

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BN_CTX_end`
- `BN_CTX_get`
- `BN_CTX_new_ex`
- `BN_CTX_secure_new`
- `BN_CTX_secure_new_ex`
- `BN_CTX_start`

Status:
- completed

Initial evidence:
- This is the next coherent BN context-management cluster without `analysis_doc`.
- It extends the same public-surface rule confirmed again in Batch 039:
  - openHiTLS has internal BN optimizer/context machinery
  - but the BN subsystem is not installed as part of the public API surface

## 1. `BN_CTX_new_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L209), [bn_ctx.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_ctx.c#L118)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1026), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1047), [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L27), [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L41), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `BN_OptimizerCreate()` plus `BN_OptimizerSetLibCtx()` is the nearest internal analogue, but the optimizer layer is not installed publicly and does not expose an OpenSSL-compatible `BN_CTX` object model.

## 2. `BN_CTX_secure_new`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L212), [bn_ctx.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_ctx.c#L150)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1026), [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L27), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: openHiTLS has no public secure/non-secure BN workspace split. `BN_OptimizerCreate()` is internal only and does not encode OpenSSL `BN_FLG_SECURE` semantics.

## 3. `BN_CTX_secure_new_ex`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L211), [bn_ctx.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_ctx.c#L140)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1026), [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1047), [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L27), [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L41), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: the closest internal pieces are still `BN_OptimizerCreate()` plus optional libctx storage, but there is no public secure-mode BN context API and no installed `BN_CTX` surface.

## 4. `BN_CTX_start`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L214), [bn_ctx.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_ctx.c#L181)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1446), [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L85), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `OptimizerStart()` is the nearest internal frame-entry primitive, but it only bumps an internal depth counter. That model is not public and does not expose OpenSSL `BN_CTX_start()` semantics.

## 5. `BN_CTX_get`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L215), [bn_ctx.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_ctx.c#L214)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1469), [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L145), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `OptimizerGetBn()` is internal only and requires an explicit `room` size. OpenSSL `BN_CTX_get()` returns an auto-sized temporary `BIGNUM *` from a public workspace abstraction.

## 6. `BN_CTX_end`
- OpenSSL declaration/implementation: [bn.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bn.h#L216), [bn_ctx.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bn/bn_ctx.c#L195)
- openHiTLS internal declaration/implementation: [crypt_bn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/include/crypt_bn.h#L1457), [bn_optimizer.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/bn/src/bn_optimizer.c#L176), [CMakeLists.txt](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/CMakeLists.txt#L96)
- Verdict: keep `not_available`
- Why: `OptimizerEnd()` is the nearest internal frame-exit primitive, but it is not public and its chunk/depth bookkeeping is not an exposed OpenSSL-compatible `BN_CTX` API.

## Batch 040 summary

Keep `not_available`:
- `BN_CTX_new_ex`
- `BN_CTX_secure_new`
- `BN_CTX_secure_new_ex`
- `BN_CTX_start`
- `BN_CTX_get`
- `BN_CTX_end`

Main observation:
- openHiTLS does have an internal BN workspace/optimizer subsystem.
- That subsystem is not part of the installed public API surface.
- Even aside from visibility, the semantics do not line up cleanly:
  - OpenSSL exposes a public `BN_CTX` object with start/get/end frame discipline
  - openHiTLS exposes internal optimizer depth/chunk primitives with explicit room sizing
