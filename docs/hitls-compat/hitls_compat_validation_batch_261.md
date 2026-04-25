# openHiTLS Compatibility Validation Batch 261

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining utility/runtime tails lacking `analysis_doc`:
  - `OpenSSL_version`
  - `OpenSSL_version_num`
  - `conf_ssl_*`
  - `err_free_strings_int`
  - `MD5_Transform`
  - `SHA1_Transform`
  - `SHA256_Transform`
  - `SHA512_Transform`

Status:
- completed

Initial evidence:
- OpenSSL exposes three unrelated utility families here:
  - version queries
  - internal SSL config table helpers
  - low-level digest compression-step helpers
- openHiTLS public installed surface exposes only one adjacent public surface:
  - `BSL_LOG_GetVersion`
  - `BSL_LOG_GetVersionNum`
- openHiTLS public digest surface in [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48) stays at whole-digest ctx operations:
  - `CRYPT_EAL_MdNewCtx`
  - `CRYPT_EAL_MdInit`
  - `CRYPT_EAL_MdUpdate`
  - `CRYPT_EAL_MdFinal`
  - `CRYPT_EAL_Md`

Verdict:
- keep `available = 0`
- keep `partial = 2`
- keep `not_available = 8`

Reasoning boundary:
- `partial` is justified for the two version-query interfaces:
  - `OpenSSL_version`
    - `BSL_LOG_GetVersion`
  - `OpenSSL_version_num`
    - `BSL_LOG_GetVersionNum`
- These stay `partial` because:
  - the formatting and numeric scheme are openHiTLS-specific
  - the APIs are close in intent but not OpenSSL-compatible drop-ins
- `not_available` remains correct for:
  - `conf_ssl_get`
  - `conf_ssl_get_cmd`
  - `conf_ssl_name_find`
  - `err_free_strings_int`
  - `MD5_Transform`
  - `SHA1_Transform`
  - `SHA256_Transform`
  - `SHA512_Transform`

Representative evidence:
- OpenSSL declarations and docs:
  - [crypto.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/crypto.h.in#L152)
  - [OpenSSL_version.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/OpenSSL_version.pod#L37)
  - [conf_ssl.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/conf/conf_ssl.c#L138)
  - [err.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/err/err.c#L328)
  - [md5.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/md5.h#L54)
  - [sha.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/sha.h#L52)
- openHiTLS public declarations:
  - [bsl_log.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_log.h#L98)
  - [bsl_log.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_log.h#L106)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L124)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L139)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L171)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L196)

Batch 261 inventory:
- total interfaces: `10`
- `partial = 2`
- `not_available = 8`
