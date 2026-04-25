# openHiTLS Compatibility Validation Batch 133

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CIPHER_description`
- `SSL_CIPHER_find`
- `SSL_CIPHER_get_auth_nid`
- `SSL_CIPHER_get_bits`
- `SSL_CIPHER_get_cipher_nid`
- `SSL_CIPHER_get_digest_nid`
- `SSL_CIPHER_get_handshake_digest`
- `SSL_CIPHER_get_id`
- `SSL_CIPHER_get_kx_nid`
- `SSL_CIPHER_get_name`
- `SSL_CIPHER_get_protocol_id`
- `SSL_CIPHER_get_version`
- `SSL_CIPHER_is_aead`
- `SSL_CIPHER_standard_name`

Status:
- completed

Initial evidence:
- OpenSSL publishes this family in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1548), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1557), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2037), and [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2178), with implementation in [ssl_ciph.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_ciph.c#L1690), [ssl_ciph.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_ciph.c#L1899), [ssl_ciph.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_ciph.c#L1941), and [ssl_ciph.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_ciph.c#L2146).
- openHiTLS exposes public cipher-suite metadata getters in [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1037), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1091), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1125), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1136), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1147), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1158), and [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1170), with implementation in [cipher_suite.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/cipher_suite.c#L2172), [cipher_suite.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/cipher_suite.c#L2230), [cipher_suite.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/cipher_suite.c#L2250), [cipher_suite.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/cipher_suite.c#L2255), [cipher_suite.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/cipher_suite.c#L2265), and [cipher_suite.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/cipher_suite.c#L2287).
- The practical replaceability boundary is clean:
  - direct public getters exist for description, display name, standard name, protocol id, and AEAD predicate
  - enum-vs-NID and version-string-vs-int differences still block straightforward substitution for several others
  - OpenSSL handshake-digest getter has no public openHiTLS analogue

Verdict:
- adjust to `available`:
  - `SSL_CIPHER_description`
  - `SSL_CIPHER_get_name`
  - `SSL_CIPHER_get_protocol_id`
  - `SSL_CIPHER_is_aead`
  - `SSL_CIPHER_standard_name`
- keep `partial`:
  - `SSL_CIPHER_find`
  - `SSL_CIPHER_get_auth_nid`
  - `SSL_CIPHER_get_bits`
  - `SSL_CIPHER_get_cipher_nid`
  - `SSL_CIPHER_get_digest_nid`
  - `SSL_CIPHER_get_id`
  - `SSL_CIPHER_get_kx_nid`
  - `SSL_CIPHER_get_version`
- keep `not_available`:
  - `SSL_CIPHER_get_handshake_digest`
