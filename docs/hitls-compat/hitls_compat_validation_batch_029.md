# openHiTLS Compatibility Validation Batch 029

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SHA256`
- `EVP_sha1`
- `EVP_md5`
- `EVP_Digest`
- `EVP_DigestInit`
- `EVP_DigestFinal`

Status:
- completed

Initial evidence:
- This batch settles the remaining helper-style digest APIs that were left outside Batch 001.
- Current scan aggregation shows:
  - `SHA256`: 14 repos
  - `EVP_sha1`: 13 repos
  - `EVP_Digest`: 10 repos
  - `EVP_DigestInit`: 10 repos
  - `EVP_DigestFinal`: 10 repos
  - `EVP_md5`: 10 repos
- The same pattern repeats across all six symbols:
  - OpenSSL exposes helper/factory interfaces around `EVP_MD *`
  - openHiTLS exposes digest algorithms through `CRYPT_MD_*` IDs and `CRYPT_EAL_Md*` entrypoints

## 1. `SHA256`
- OpenSSL declaration/implementation: [sha.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/sha.h#L82), [sha1_one.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/sha/sha1_one.c#L56)
- openHiTLS declaration/implementation: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L196), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L72), [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L322)
- Verdict: keep `partial`
- Why: openHiTLS can compute the same one-shot digest via `CRYPT_EAL_Md(CRYPT_MD_SHA256, ...)`, but OpenSSL `SHA256()` returns `md` or a static internal buffer when `md == NULL`, which openHiTLS does not emulate.

## 2. `EVP_sha1`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L911), [legacy_sha.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/legacy_sha.c#L97)
- openHiTLS declaration/implementation: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L70), [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L102), [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L181)
- Verdict: keep `partial`
- Why: openHiTLS exposes the same algorithm as `CRYPT_MD_SHA1`, but not as an `EVP_MD *` factory function.

## 3. `EVP_md5`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L904), [legacy_md5.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/legacy_md5.c#L31)
- openHiTLS declaration/implementation: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L69), [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L99), [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L181)
- Verdict: keep `partial`
- Why: same reason as `EVP_sha1`: same digest algorithm, different API shape.

## 4. `EVP_Digest`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L714), [digest.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/digest.c#L646)
- openHiTLS declaration/implementation: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L196), [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L322)
- Verdict: keep `partial`
- Why: openHiTLS provides the same one-shot capability via `CRYPT_EAL_Md(id, in, inLen, out, outLen)`, but callers must convert `EVP_MD *` to a `CRYPT_MD_*` id and adapt output-length handling.

## 5. `EVP_DigestInit`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L722), [digest.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/digest.c#L364)
- openHiTLS declaration/implementation: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L40), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L124), [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L174)
- Verdict: keep `partial`
- Why: the closest public replacement is a composed path:
  - `CRYPT_EAL_MdNewCtx(CRYPT_MD_*)`
  - `CRYPT_EAL_MdInit(ctx)`
  OpenSSL folds digest selection and init into one API; openHiTLS splits them.

## 6. `EVP_DigestFinal`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L723), [digest.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/digest.c#L416)
- openHiTLS declaration/implementation: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L171), [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L220)
- Verdict: keep `partial`
- Why: openHiTLS can finalize and output the digest, but OpenSSL `EVP_DigestFinal()` also resets the ctx afterwards, while openHiTLS leaves the ctx in `FINAL` state.

## Batch 029 summary

Keep `partial`:
- `SHA256`
- `EVP_sha1`
- `EVP_md5`
- `EVP_Digest`
- `EVP_DigestInit`
- `EVP_DigestFinal`

Main observation:
- This batch is another clean example of “behavioral equivalence, interface mismatch”.
- No status upgrades are justified, but `EVP_DigestInit` does need the composed-public-api expression in the mapping.
