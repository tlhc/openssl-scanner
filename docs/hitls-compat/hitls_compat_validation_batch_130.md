# openHiTLS Compatibility Validation Batch 130

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `MD5`
- `MD5_Init`
- `MD5_Update`
- `MD5_Final`
- `SHA1`
- `SHA1_Init`
- `SHA1_Update`
- `SHA1_Final`
- `SHA224`
- `SHA224_Init`
- `SHA224_Update`
- `SHA224_Final`
- `SHA256`
- `SHA256_Init`
- `SHA256_Update`
- `SHA256_Final`
- `SHA384`
- `SHA384_Init`
- `SHA384_Update`
- `SHA384_Final`
- `SHA512`
- `SHA512_Init`
- `SHA512_Update`
- `SHA512_Final`

Status:
- completed

Initial evidence:
- OpenSSL exposes the low-level one-shot and context-style digest family in [md5.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/md5.h#L49) and [sha.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/sha.h#L49).
- openHiTLS publicly exposes one-shot digest and digest-context composition in [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L124), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L139), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L171), and [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L196).
- openHiTLS publicly exposes the required digest algorithm ids in [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L69), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L70), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L71), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L72), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L73), and [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L74).
- openHiTLS EAL implementation wires those public ids into working methods in [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L68), [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L71), [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L74), [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L77), [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L80), and [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L83).
- Under the current truth-library rule, a public multi-call composition counts as `available` only when it remains practically substitutable for developers, rather than merely proving that the underlying crypto capability exists.

Verdict:
- adjust all entries in scope to `available`.
- The supported composition rule is:
  - one-shot helpers: `CRYPT_EAL_Md(CRYPT_MD_*, ...)`
  - init/update/final helpers: `CRYPT_EAL_MdNewCtx(CRYPT_MD_*) + CRYPT_EAL_MdInit + CRYPT_EAL_MdUpdate + CRYPT_EAL_MdFinal`
