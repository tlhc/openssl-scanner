# openHiTLS Compatibility Validation Batch 135

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CONF_CTX_clear_flags`
- `SSL_CONF_CTX_finish`
- `SSL_CONF_CTX_free`
- `SSL_CONF_CTX_new`
- `SSL_CONF_CTX_set1_prefix`
- `SSL_CONF_CTX_set_flags`
- `SSL_CONF_CTX_set_ssl`
- `SSL_CONF_CTX_set_ssl_ctx`
- `SSL_CONF_cmd`
- `SSL_CONF_cmd_argv`
- `SSL_CONF_cmd_value_type`

Status:
- completed

Initial evidence:
- OpenSSL publishes the `SSL_CONF` command/configuration surface in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2232) and implements it in [ssl_conf.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_conf.c#L882), [ssl_conf.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_conf.c#L964), and [ssl_conf.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_conf.c#L1016).
- openHiTLS exposes typed configuration setters such as [HITLS_CFG_SetCipherSuites](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L817) and [HITLS_SetCipherSuites](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L670), but no public command-string configuration interpreter or `SSL_CONF_CTX` analogue.
- Under the current replaceability rule, the presence of typed setters is insufficient because OpenSSL `SSL_CONF*` is a developer-facing command surface and openHiTLS has no practically substitutable public wrapper.

Verdict:
- keep `not_available` for all entries in scope.
