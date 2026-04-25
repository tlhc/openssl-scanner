# openHiTLS Compatibility Validation Batch 136

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CTX_SRP_CTX_free`
- `SSL_CTX_SRP_CTX_init`
- `SSL_CTX_add1_to_CA_list`
- `SSL_CTX_add_client_CA`
- `SSL_CTX_add_client_custom_ext`
- `SSL_CTX_add_custom_ext`
- `SSL_CTX_add_server_custom_ext`
- `SSL_CTX_add_session`
- `SSL_CTX_callback_ctrl`
- `SSL_CTX_clear_options`
- `SSL_CTX_config`
- `SSL_CTX_ctrl`
- `SSL_CTX_flush_sessions`
- `SSL_CTX_flush_sessions_ex`
- `SSL_CTX_get0_CA_list`
- `SSL_CTX_get0_param`
- `SSL_CTX_get0_security_ex_data`

Status:
- completed

Initial evidence:
- OpenSSL publishes this mixed `SSL_CTX_*` family in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L580), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L858), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1705), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2016), and [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2249), with implementation in [ssl_cert.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_cert.c#L574), [extensions_cust.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/statem/extensions_cust.c#L448), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L699), and [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4925).
- openHiTLS exposes public CA indication / CA list APIs in [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L905), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L914), and [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L925).
- openHiTLS exposes public custom-extension registration in [hitls_custom_extensions.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_custom_extensions.h#L152), [hitls_custom_extensions.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_custom_extensions.h#L174), and [hitls_custom_extensions.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_custom_extensions.h#L188), with implementation in [custom_extensions.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/custom_extensions/src/custom_extensions.c#L95).
- openHiTLS exposes public mode/session/security-ex-data helpers in [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1229), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L714), and [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L202).
- No public SRP surface, no generic `callback_ctrl`, no `SSL_CTX_config`-style named profile/config parser, and no generic `SSL_CTX_ctrl` dispatcher were found in openHiTLS.

Verdict:
- adjust to `available`:
  - `SSL_CTX_add_client_custom_ext`
  - `SSL_CTX_add_custom_ext`
  - `SSL_CTX_add_server_custom_ext`
  - `SSL_CTX_flush_sessions`
  - `SSL_CTX_flush_sessions_ex`
  - `SSL_CTX_get0_security_ex_data`
- keep `partial`:
  - `SSL_CTX_add1_to_CA_list`
  - `SSL_CTX_add_client_CA`
  - `SSL_CTX_clear_options`
  - `SSL_CTX_get0_CA_list`
- keep `not_available`:
  - `SSL_CTX_SRP_CTX_free`
  - `SSL_CTX_SRP_CTX_init`
  - `SSL_CTX_add_session`
  - `SSL_CTX_callback_ctrl`
  - `SSL_CTX_config`
  - `SSL_CTX_ctrl`
  - `SSL_CTX_get0_param`
