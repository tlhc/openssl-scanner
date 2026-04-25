# openHiTLS Compatibility Validation Batch 033

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `EVP_DigestSignInit`
- `EVP_DigestVerifyInit`
- `EVP_DigestSignFinal`
- `EVP_DigestSignUpdate`
- `EVP_DigestVerifyFinal`
- `EVP_PKEY_verify`
- `EVP_PKEY_verify_init`

Status:
- completed

Initial evidence:
- This family is the next coherent high-frequency group without `analysis_doc`.
- Current scan aggregation shows:
  - `EVP_DigestSignInit`: 11 repos
  - `EVP_DigestVerifyInit`: 10 repos
  - `EVP_PKEY_verify`: 8 repos
  - `EVP_DigestSignFinal`: 8 repos
  - `EVP_DigestVerifyFinal`: 8 repos
  - `EVP_PKEY_verify_init`: 8 repos
  - `EVP_DigestSignUpdate`: 8 repos
- The likely decision surface is:
  - one-shot sign/verify via `CRYPT_EAL_PkeySign*` / `CRYPT_EAL_PkeyVerify*`
  - streaming `DigestSignUpdate` may remain partial with null replacement if openHiTLS still has no streaming sign API
  - init/final helpers probably remain partial because openHiTLS binds hash/pkey semantics differently

## 1. `EVP_DigestSignInit`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L824), [m_sigver.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/m_sigver.c#L383)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L365), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L57)
- Verdict: keep `partial`
- Why: OpenSSL creates a digest-sign context and can stream through `Update`/`Final`; openHiTLS exposes a one-shot `CRYPT_EAL_PkeySign` entry point instead.

## 2. `EVP_DigestVerifyInit`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L835), [m_sigver.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/m_sigver.c#L399)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L382), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L78)
- Verdict: keep `partial`
- Why: openHiTLS verifies in a single public call instead of creating a digest-verify context.

## 3. `EVP_DigestSignFinal`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L828), [m_sigver.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/m_sigver.c#L468)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L365), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L57)
- Verdict: keep `partial`
- Why: OpenSSL finalizes a streamed digest-sign operation; openHiTLS has no streamed signing state to finalize.

## 4. `EVP_DigestSignUpdate`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L827), [m_sigver.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/m_sigver.c#L407)
- openHiTLS declaration/implementation: none found in `include/crypto/crypt_eal_pkey.h` or `crypto/eal/src/eal_pkey_sign.c`
- Verdict: keep `partial`
- Why: a negative search for `PkeySignInit`, `PkeySignUpdate`, and `PkeySignFinal` found no openHiTLS streaming-sign API; the closest usable path is to buffer data and call `CRYPT_EAL_PkeySign`.

## 5. `EVP_DigestVerifyFinal`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L839), [m_sigver.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/m_sigver.c#L592)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L382), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L78)
- Verdict: keep `partial`
- Why: OpenSSL finalizes a digest-verify context; openHiTLS exposes only the one-shot verify call.

## 6. `EVP_PKEY_verify`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1897), [signature.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/signature.c#L674)
- openHiTLS declaration/implementation: [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L420), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L100)
- Verdict: keep `partial`
- Why: openHiTLS provides `CRYPT_EAL_PkeyVerifyData` with a different argument shape and key-context model, so this is capability-equivalent but not API-equivalent.

## 7. `EVP_PKEY_verify_init`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1895), [signature.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/signature.c#L664)
- openHiTLS declaration/implementation: none found in `include/crypto/crypt_eal_pkey.h` or `crypto/eal/src/eal_pkey_sign.c`
- Verdict: keep `partial`
- Why: openHiTLS does not expose a separate verify-init primitive; verify runs directly through `CRYPT_EAL_PkeyVerify` / `CRYPT_EAL_PkeyVerifyData`.

## Batch 033 summary

Keep `partial`:
- `EVP_DigestSignInit`
- `EVP_DigestVerifyInit`
- `EVP_DigestSignFinal`
- `EVP_DigestSignUpdate`
- `EVP_DigestVerifyFinal`
- `EVP_PKEY_verify`
- `EVP_PKEY_verify_init`

Main observation:
- openHiTLS exposes one-shot EAL signing/verifying APIs, not OpenSSL's digest-sign state machine.
- The only direct coverage is capability-level, not a drop-in symbol match.
