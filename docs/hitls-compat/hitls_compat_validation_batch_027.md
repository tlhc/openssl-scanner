# openHiTLS Compatibility Validation Batch 027

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `HMAC_CTX_new`
- `HMAC_CTX_free`
- `HMAC_Init_ex`
- `HMAC_Update`
- `HMAC_Final`
- `HMAC`

Status:
- completed

Initial evidence:
- OpenSSL exports this family in [hmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/hmac.h#L33) with the classic `ctx + md + key` lifecycle and a one-shot `HMAC(...)` helper.
- openHiTLS exposes the closest public surface through [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L57), backed by HMAC implementations in [crypt_hmac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hmac/include/crypt_hmac.h#L35) and [hmac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hmac/src/hmac.c#L40).
- The main semantic difference is that openHiTLS binds the hash algorithm when creating the MAC context via `CRYPT_MAC_AlgId`, while OpenSSL defers digest selection to `HMAC_Init_ex`.

## 1. `HMAC_CTX_new`
- OpenSSL declaration/implementation: [hmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/hmac.h#L33), [hmac.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/hmac/hmac.c#L145)
- openHiTLS declaration/implementation: [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L57), [eal_mac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_mac.c#L90)
- Verdict: keep `partial`
- Why: `CRYPT_EAL_MacNewCtx` requires a concrete `CRYPT_MAC_HMAC_*` algorithm ID at creation time, while `HMAC_CTX_new()` creates an untyped context and leaves digest selection to later initialization.

## 2. `HMAC_CTX_free`
- OpenSSL declaration/implementation: [hmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/hmac.h#L35), [hmac.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/hmac/hmac.c#L166)
- openHiTLS declaration/implementation: [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L78), [eal_mac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_mac.c#L101)
- Verdict: change to `available`
- Why: both are direct, void-returning, null-safe release APIs for the MAC context object. Unlike `HMAC_CTX_new`, this step does not depend on deferred digest binding.

## 3. `HMAC_Init_ex`
- OpenSSL declaration/implementation: [hmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/hmac.h#L43), [hmac.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/hmac/hmac.c#L25)
- openHiTLS declaration/implementation: [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L102), [eal_mac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_mac.c#L115), [crypt_hmac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hmac/include/crypt_hmac.h#L38), [hmac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hmac/src/hmac.c#L177)
- Verdict: keep `partial`
- Why: openHiTLS can initialize the HMAC state with key material, but hash selection moved to `CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_*)` and there is no OpenSSL-style `ENGINE *impl` parameter. Functionally equivalent, contract not identical.

## 4. `HMAC_Update`
- OpenSSL declaration/implementation: [hmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/hmac.h#L45), [hmac.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/hmac/hmac.c#L110)
- openHiTLS declaration/implementation: [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L122), [eal_mac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_mac.c#L136), [crypt_hmac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hmac/include/crypt_hmac.h#L39), [hmac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hmac/src/hmac.c#L183)
- Verdict: keep `partial`
- Why: same streaming-update role, but openHiTLS returns status codes and enforces its own `NEW/INIT/UPDATE/FINAL` state machine around the generic MAC wrapper.

## 5. `HMAC_Final`
- OpenSSL declaration/implementation: [hmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/hmac.h#L47), [hmac.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/hmac/hmac.c#L117)
- openHiTLS declaration/implementation: [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L151), [eal_mac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_mac.c#L162), [crypt_hmac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hmac/include/crypt_hmac.h#L40), [hmac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/hmac/src/hmac.c#L192)
- Verdict: keep `partial`
- Why: same finalize-and-output step, but openHiTLS uses `uint32_t *len` plus status codes and is mediated through the generic MAC ctx state machine.

## 6. `HMAC`
- OpenSSL declaration/implementation: [hmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/hmac.h#L54), [hmac.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/hmac/hmac.c#L221)
- openHiTLS declaration/implementation: [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L57), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L102), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L122), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L151)
- Verdict: keep `partial`
- Why: openHiTLS can realize the same one-shot HMAC functionality only as a composed public pipeline:
  - `CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_*)`
  - `CRYPT_EAL_MacInit`
  - `CRYPT_EAL_MacUpdate`
  - `CRYPT_EAL_MacFinal`
  There is no single OpenSSL-shaped helper function.

## Batch 027 summary

Change to `available`:
- `HMAC_CTX_free`

Keep `partial`:
- `HMAC_CTX_new`
- `HMAC_Init_ex`
- `HMAC_Update`
- `HMAC_Final`
- `HMAC`

Main observation:
- The HMAC family is mostly a clean functional match.
- The reason most entries stay `partial` is the algorithm-binding split:
  - OpenSSL: create untyped ctx, pick digest at `HMAC_Init_ex`
  - openHiTLS: choose `CRYPT_MAC_HMAC_*` first, then init/update/final on that typed ctx
