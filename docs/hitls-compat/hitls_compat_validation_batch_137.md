# openHiTLS Compatibility Validation Batch 137

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CTX_get1_compressed_cert`
- `SSL_CTX_get_ciphers`
- `SSL_CTX_get_default_passwd_cb`
- `SSL_CTX_get_default_passwd_cb_userdata`
- `SSL_CTX_get_keylog_callback`
- `SSL_CTX_get_max_early_data`
- `SSL_CTX_get_record_padding_callback_arg`
- `SSL_CTX_get_recv_max_early_data`
- `SSL_CTX_get_ssl_method`
- `SSL_CTX_has_client_custom_ext`
- `SSL_CTX_load_verify_dir`
- `SSL_CTX_load_verify_file`
- `SSL_CTX_load_verify_store`
- `SSL_CTX_new_ex`
- `SSL_CTX_remove_session`

Status:
- completed

Initial evidence:
- OpenSSL publishes these getters/config helpers in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1532), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1754), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1989), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2063), and [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2210), with implementation in [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L2715), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3201), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3524), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4423), and [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L786).
- openHiTLS exposes direct public getters/loaders for password callbacks, record-padding callback arg, verify file/dir loading, provider config construction, cipher-suite enumeration, and session removal in [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L247), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L267), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1396), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1438), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L451), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L829), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1588), and [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L725).
- No public keylog callback getter, no max-early-data getter, no SSL_METHOD object model, no custom-extension presence query, and no verify-store loader with OpenSSL store semantics were found in openHiTLS.

Verdict:
- adjust to `available`:
  - `SSL_CTX_get_default_passwd_cb`
  - `SSL_CTX_get_default_passwd_cb_userdata`
  - `SSL_CTX_get_record_padding_callback_arg`
  - `SSL_CTX_load_verify_dir`
  - `SSL_CTX_load_verify_file`
  - `SSL_CTX_remove_session`
- keep `partial`:
  - `SSL_CTX_get_ciphers`
  - `SSL_CTX_new_ex`
- keep `not_available`:
  - `SSL_CTX_get1_compressed_cert`
  - `SSL_CTX_get_keylog_callback`
  - `SSL_CTX_get_max_early_data`
  - `SSL_CTX_get_recv_max_early_data`
  - `SSL_CTX_get_ssl_method`
  - `SSL_CTX_has_client_custom_ext`
  - `SSL_CTX_load_verify_store`
