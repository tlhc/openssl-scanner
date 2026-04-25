# openHiTLS Compatibility Validation Batch 008

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `EVP_CIPHER_CTX_new`
- `EVP_CIPHER_CTX_free`
- `EVP_CIPHER_CTX_ctrl`
- `EVP_CIPHER_CTX_set_padding`
- `EVP_EncryptInit_ex`
- `EVP_DecryptInit_ex`
- `EVP_MD_CTX_new`
- `EVP_MD_CTX_free`
- `EVP_sha256`
- `EVP_sha384`
- `EVP_sha512`

Status:
- completed

Initial evidence:
- OpenSSL declarations are concentrated in [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L696), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L751), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L768), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L873), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L877), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L878), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L913), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L914), and [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L915).
- openHiTLS public replacements are in:
  - [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57)
  - [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L79)
  - [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220)
  - [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L231)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L114)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L72)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L73)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L74)
- Current mapping baseline is uniformly `partial`, which is plausible but too coarse. The main questions are whether the alloc/free getters are already direct enough for `available`, and whether algorithm-selector functions like `EVP_sha256()` should stay `partial` because openHiTLS uses enum IDs instead of method objects.

## 1. `EVP_CIPHER_CTX_new`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_CipherNewCtx`

Verified evidence:
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L873), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L69)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L90)

Verdict:
- Keep `partial`

Why:
- openHiTLS requires the cipher algorithm ID at construction time.
- OpenSSL allocates an untyped context and binds the algorithm later.

## 2. `EVP_CIPHER_CTX_free`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_CipherFreeCtx`

Verified evidence:
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L875), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L74)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L79), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L101)

Verdict:
- Change to `available`

Why:
- Both are public void destructors for the cipher context and are NULL-safe.

## 3. `EVP_CIPHER_CTX_ctrl`

Current JSON:
- `status = partial`

Verified evidence:
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L878), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L1052)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L306)

Verdict:
- Keep `partial`

Why:
- The control surface is public on both sides.
- Control codes, argument conventions, and state-transition rules are materially different.

## 4. `EVP_CIPHER_CTX_set_padding`

Current JSON:
- `status = partial`

Verified evidence:
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L877), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L1033)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L231), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L339)

Verdict:
- Change to `available`

Why:
- The public role matches exactly: configure padding behavior on an existing cipher context.
- The only mismatch is thin adaptation from OpenSSL `int` to openHiTLS `CRYPT_PaddingType`.

## 5. `EVP_EncryptInit_ex`

Current JSON:
- `status = partial`

Verified evidence:
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L751), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L446)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L91), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L113)

Verdict:
- Keep `partial`

Why:
- openHiTLS requires explicit key/iv lengths and a pre-selected algorithm in the context.
- OpenSSL allows the algorithm to be supplied here and has legacy engine semantics.

## 6. `EVP_DecryptInit_ex`

Current JSON:
- `status = partial`

Verified evidence:
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L768), [evp_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/evp_enc.c#L466)
- openHiTLS declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L91), [eal_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_cipher.c#L113)

Verdict:
- Keep `partial`

Why:
- Same mismatch profile as `EVP_EncryptInit_ex`.

## 7. `EVP_MD_CTX_new`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_MdNewCtx`

Verified evidence:
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L696), [digest.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/digest.c#L130)
- openHiTLS declaration/implementation: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48), [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L80)

Verdict:
- Keep `partial`

Why:
- openHiTLS requires the digest algorithm ID at creation time.
- OpenSSL allocates an untyped digest context and binds the algorithm later.

## 8. `EVP_MD_CTX_free`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_MdFreeCtx`

Verified evidence:
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L698), [digest.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/digest.c#L135)
- openHiTLS declaration/implementation: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L114), [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L160)

Verdict:
- Change to `available`

Why:
- Both are public void destructors for the digest context and are NULL-safe.

## 9. `EVP_sha256`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L913), [legacy_sha.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/legacy_sha.c#L127)
- openHiTLS replacement form: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L72)
- Verdict: keep `partial`
- Why: openHiTLS exposes an algorithm ID enum, not an `EVP_MD *` method object.

## 10. `EVP_sha384`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L914), [legacy_sha.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/legacy_sha.c#L172)
- openHiTLS replacement form: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L73)
- Verdict: keep `partial`
- Why: same reason as `EVP_sha256`.

## 11. `EVP_sha512`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L915), [legacy_sha.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/legacy_sha.c#L187)
- openHiTLS replacement form: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L74)
- Verdict: keep `partial`
- Why: same reason as `EVP_sha256`.

## Batch 008 summary

Change to `available`:
- `EVP_CIPHER_CTX_free`
- `EVP_CIPHER_CTX_set_padding`
- `EVP_MD_CTX_free`

Keep `partial`:
- `EVP_CIPHER_CTX_new`
- `EVP_CIPHER_CTX_ctrl`
- `EVP_EncryptInit_ex`
- `EVP_DecryptInit_ex`
- `EVP_MD_CTX_new`
- `EVP_sha256`
- `EVP_sha384`
- `EVP_sha512`

Main observation:
- openHiTLS EAL is strong on lifecycle and mode-setting APIs once the algorithm-specific context exists.
- The main gap is OpenSSL’s late-bound method-object model; openHiTLS makes the algorithm ID part of context construction instead.
