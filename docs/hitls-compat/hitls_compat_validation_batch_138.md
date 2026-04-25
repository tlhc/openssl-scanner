# openHiTLS Compatibility Validation Batch 138

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CTX_sessions`
- `SSL_CTX_set0_ctlog_store`
- `SSL_CTX_set0_security_ex_data`
- `SSL_CTX_set0_tmp_dh_pkey`
- `SSL_CTX_set1_cert_comp_preference`
- `SSL_CTX_set1_cert_store`
- `SSL_CTX_set1_client_cert_type`
- `SSL_CTX_set1_compressed_cert`
- `SSL_CTX_set1_param`
- `SSL_CTX_set1_server_cert_type`
- `SSL_CTX_set_allow_early_data_cb`
- `SSL_CTX_set_async_callback`
- `SSL_CTX_set_async_callback_arg`
- `SSL_CTX_set_block_padding`
- `SSL_CTX_set_cert_store`
- `SSL_CTX_set_client_hello_cb`
- `SSL_CTX_set_cookie_generate_cb`
- `SSL_CTX_set_cookie_verify_cb`
- `SSL_CTX_set_ct_validation_callback`
- `SSL_CTX_set_default_passwd_cb`
- `SSL_CTX_set_default_passwd_cb_userdata`

Status:
- completed

Initial evidence:
- OpenSSL publishes this `SSL_CTX` setter/control family in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L675), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L733), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1489), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1539), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1752), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1853), and [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2441).
- openHiTLS exposes direct public setters for security ex-data, temp DH, stores, default password callbacks, client hello callback, cookie callbacks, and record-padding callback machinery in [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L193), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L651), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L135), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L238), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L985), [hitls_cookie.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cookie.h#L72), and [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1557).
- No public session-cache handle accessor, no CT log store setter, no X509_VERIFY_PARAM setter, no early-data callback setter, and no ASYNC surface were found in openHiTLS.

Verdict:
- adjust to `available`:
  - `SSL_CTX_set0_security_ex_data`
  - `SSL_CTX_set_client_hello_cb`
  - `SSL_CTX_set_cookie_generate_cb`
  - `SSL_CTX_set_cookie_verify_cb`
  - `SSL_CTX_set_default_passwd_cb`
  - `SSL_CTX_set_default_passwd_cb_userdata`
- keep `partial`:
  - `SSL_CTX_set0_tmp_dh_pkey`
  - `SSL_CTX_set1_cert_store`
  - `SSL_CTX_set_block_padding`
  - `SSL_CTX_set_cert_store`
- keep `not_available`:
  - `SSL_CTX_sessions`
  - `SSL_CTX_set0_ctlog_store`
  - `SSL_CTX_set1_cert_comp_preference`
  - `SSL_CTX_set1_client_cert_type`
  - `SSL_CTX_set1_compressed_cert`
  - `SSL_CTX_set1_param`
  - `SSL_CTX_set1_server_cert_type`
  - `SSL_CTX_set_allow_early_data_cb`
  - `SSL_CTX_set_async_callback`
  - `SSL_CTX_set_async_callback_arg`
  - `SSL_CTX_set_ct_validation_callback`
