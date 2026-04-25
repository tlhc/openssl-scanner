# openHiTLS Compatibility Validation Batch 142

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `OpenSSL_add_all_algorithms`
- `OpenSSL_add_ssl_algorithms`
- `SSL_library_init`
- `SSL_load_error_strings`
- `ERR_load_crypto_strings`
- `SSL_CTX_set_mode`
- `SSL_CTX_set1_curves_list`
- `SSL_CTX_set_max_proto_version`
- `SSL_CTX_set_min_proto_version`
- `SSL_get_peer_certificate`
- `SSL_get_cipher`
- `SSL_set_tlsext_host_name`
- `SSL_get_app_data`
- `SSL_set_app_data`
- `SSL_want_read`
- `SSL_want_write`
- `SSL_set_mtu`
- `SSL_get_shared_sigalgs`

Status:
- completed

Initial evidence:
- OpenSSL exposes the legacy bootstrap aliases and SSL helper macros in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1116), [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L1163), [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L1168), [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L1538), [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L1728), [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L1813), and [tls1.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/tls1.h#L299).
- openHiTLS exposes public split bootstrap and error surfaces in [bsl_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_init.h#L42), [crypt_eal_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_init.h#L51), [hitls_crypt_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_crypt_init.h#L36), [hitls_cert_init.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_init.h#L36), and [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L67).
- openHiTLS exposes direct public SSL/TLS replacement surfaces in [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L529), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L879), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1091), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1219), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L257), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L272), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L704), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L806), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1201), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1345), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L448), and [hitls_type.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_type.h#L170).

Verdict:
- adjust to `available`:
  - `SSL_CTX_set_mode`
  - `SSL_CTX_set1_curves_list`
  - `SSL_get_peer_certificate`
  - `SSL_get_cipher`
  - `SSL_set_tlsext_host_name`
  - `SSL_get_app_data`
  - `SSL_set_app_data`
  - `SSL_want_read`
  - `SSL_want_write`
  - `SSL_set_mtu`
  - `SSL_get_shared_sigalgs`
- adjust to `partial`:
  - `OpenSSL_add_all_algorithms`
  - `OpenSSL_add_ssl_algorithms`
  - `SSL_library_init`
  - `SSL_load_error_strings`
  - `ERR_load_crypto_strings`
  - `SSL_CTX_set_max_proto_version`
  - `SSL_CTX_set_min_proto_version`

Reasoning boundary:
- The legacy bootstrap aliases were not kept as `available` because openHiTLS only exposes the corresponding setup as multiple public initialization surfaces, not as one-call aliases.
- The `SSL_CTX_*` protocol-version setters were not kept as `available` because openHiTLS exposes public min/max configuration through `HITLS_CFG_SetVersion`, but not as one-sided min-only / max-only config setters.
- The rest crossed into `available` because openHiTLS already exposes direct public config or ctx APIs with practical substitution paths for real callers.
