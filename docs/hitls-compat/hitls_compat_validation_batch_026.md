# openHiTLS Compatibility Validation Batch 026

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `RAND_bytes`
- `RAND_bytes_ex`
- `RAND_priv_bytes`
- `RAND_priv_bytes_ex`
- `RAND_seed`
- `RAND_add`
- `RAND_poll`
- `RAND_status`

Status:
- completed

Initial evidence:
- This family has the highest remaining real-repo frequency among entries that still lacked `analysis_doc`.
- Current scan aggregation shows:
  - `RAND_bytes`: 32 repos
  - `RAND_priv_bytes`: 10 repos
  - `RAND_seed`: 5 repos
  - `RAND_status`: 5 repos
  - `RAND_add`: 3 repos
  - `RAND_poll`: 3 repos
- OpenSSL splits its default RNG stack into `primary`, `public`, and `private` DRBG instances in [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L385).
- openHiTLS exposes one global DRBG and one libctx-scoped DRBG handle through `g_globalRndCtx` and `localCtx->drbg` in [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L491) and [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L915); there is no public/private split.

## 1. `RAND_bytes`
- OpenSSL declaration/implementation: [rand.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rand.h#L61), [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L376)
- openHiTLS declaration/implementation: [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L190), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L553), [eal_rand_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand_method.c#L43)
- Verdict: keep `partial`
- Why: same function-level capability exists, but openHiTLS uses status-code returns, `uint32_t` length, and a single global DRBG instead of OpenSSL's public DRBG path.

## 2. `RAND_bytes_ex`
- OpenSSL declaration/implementation: [rand.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rand.h#L75), [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L354)
- openHiTLS declaration/implementation: [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L204), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L915)
- Verdict: keep `partial`
- Why: openHiTLS provides libctx-scoped random-byte generation, but it does not accept OpenSSL's `strength` parameter and still uses a single DRBG per libctx rather than OpenSSL's public/private split.

## 3. `RAND_priv_bytes`
- OpenSSL declaration/implementation: [rand.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rand.h#L62), [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L347)
- openHiTLS declaration/implementation: [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L190), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L553)
- Verdict: keep `partial`
- Why: openHiTLS can generate cryptographically secure bytes, but it does not provide the dedicated private-DRBG isolation that OpenSSL promises for secret material.

## 4. `RAND_priv_bytes_ex`
- OpenSSL declaration/implementation: [rand.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rand.h#L68), [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L325)
- openHiTLS declaration/implementation: [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L204), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L915)
- Verdict: change to `partial`
- Why: the closest public replacement is `CRYPT_EAL_RandbytesEx(libCtx, ...)`, which matches libctx-scoped random-byte generation, but openHiTLS still lacks OpenSSL's separate private DRBG and strength parameter.

## 5. `RAND_seed`
- OpenSSL declaration/implementation: [rand.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rand.h#L91), [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L245)
- openHiTLS declaration/implementation: [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L218), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L563), [eal_rand_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand_method.c#L33)
- Verdict: keep `partial`
- Why: caller-supplied bytes can be mixed into RNG state through `CRYPT_EAL_RandSeedWithAdin`, but openHiTLS models them as additional input during reseed, not as OpenSSL's seed API with legacy semantics.

## 6. `RAND_add`
- OpenSSL declaration/implementation: [rand.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rand.h#L97), [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L262)
- openHiTLS declaration/implementation: [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L218), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L563)
- Verdict: keep `partial`
- Why: `CRYPT_EAL_RandSeedWithAdin` provides the same broad function of injecting caller-provided bytes into reseeding, but openHiTLS has no `randomness` estimate parameter.

## 7. `RAND_poll`
- OpenSSL declaration/implementation: [rand.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rand.h#L109), [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L121)
- openHiTLS declaration/implementation: [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L231), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L572), [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L107)
- Verdict: keep `partial`
- Why: openHiTLS has no dedicated `poll` API, but `CRYPT_EAL_RandSeed()` reseeds from the configured entropy source, which is the closest public function-level replacement.

## 8. `RAND_status`
- OpenSSL declaration/implementation: [rand.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rand.h#L101), [rand_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/rand/rand_lib.c#L296)
- openHiTLS declaration/implementation: [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L390), [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L400), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L638), [eal_rand.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_rand.c#L658), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L737)
- Verdict: change to `partial`
- Why: openHiTLS has no single `RAND_status` convenience API, but callers can compose `CRYPT_EAL_GetSeedCtx(...) + CRYPT_EAL_DrbgCtrl(..., CRYPT_CTRL_GET_WORKING_STATUS, ...)` to query whether the DRBG is working. That is still weaker than OpenSSL's exact ready-state semantics.

## Batch 026 summary

Keep `partial`:
- `RAND_bytes`
- `RAND_bytes_ex`
- `RAND_priv_bytes`
- `RAND_seed`
- `RAND_add`
- `RAND_poll`

Change to `partial`:
- `RAND_priv_bytes_ex`
- `RAND_status`

Main observation:
- openHiTLS public RAND coverage is broader than the old map suggested.
- The main gaps are semantic, not functional:
  - no public/private DRBG separation like OpenSSL
  - no direct `RAND_status` convenience function
  - no `strength` parameter on `RandbytesEx`
