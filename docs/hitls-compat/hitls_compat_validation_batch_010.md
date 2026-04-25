# openHiTLS Compatibility Validation Batch 010

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CTX_set_cipher_list`
- `SSL_CTX_set_ciphersuites`
- `SSL_CTX_set_alpn_protos`
- `SSL_CTX_set_alpn_select_cb`
- `SSL_CTX_set_client_CA_list`
- `SSL_CTX_set_client_cert_cb`
- `SSL_CTX_set_cert_verify_callback`
- `SSL_CTX_set_default_read_buffer_len`
- `SSL_CTX_set_num_tickets`
- `SSL_CTX_set_verify_depth`

Status:
- completed

## 1. `SSL_CTX_set_cipher_list`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1530), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L2743)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L817), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L863)
- Verdict: keep `partial`
- Why: openHiTLS takes a numeric `uint16_t` cipher-suite array, not OpenSSL’s cipher-list string DSL.

## 2. `SSL_CTX_set_ciphersuites`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1579), [ssl_ciph.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_ciph.c#L1414)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L817), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L863)
- Verdict: keep `partial`
- Why: same mismatch profile as `SSL_CTX_set_cipher_list`.

## 3. `SSL_CTX_set_alpn_protos`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L792), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3044)
- openHiTLS declaration/implementation: [hitls_alpn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_alpn.h#L71), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L156)
- Verdict: change to `available`
- Why: both set the wire-format ALPN protocol list on the TLS configuration object.

## 4. `SSL_CTX_set_alpn_select_cb`
- Current JSON: `partial`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L802)
- openHiTLS declaration/implementation: [hitls_alpn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_alpn.h#L57), [hitls_alpn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_alpn.h#L84), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L190)
- Verdict: change to `available`
- Why: both publicly register a server-side ALPN selection callback plus user arg.

## 5. `SSL_CTX_set_client_CA_list`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2022), [ssl_cert.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_cert.c#L522)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L925), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L848)
- Verdict: keep `partial`
- Why: both set client-CA hints, but openHiTLS uses `HITLS_TrustedCAList` rather than `STACK_OF(X509_NAME)`.

## 6. `SSL_CTX_set_client_cert_cb`
- Current JSON: `partial`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L725)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L943), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L704)
- Verdict: keep `partial`
- Why: current best mapping is still `HITLS_CFG_SetCertCb`, but the callback contract is broader than OpenSSL’s client-cert callback.

## 7. `SSL_CTX_set_cert_verify_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1731), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3554)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L967), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L979)
- Verdict: change to `available`
- Why: `HITLS_CFG_SetCertVerifyCb` matches the “application verification callback plus arg” shape much better than the old mapping.

## 8. `SSL_CTX_set_default_read_buffer_len`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2148), [rec_layer_s3.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/record/rec_layer_s3.c#L141)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1479), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L606)
- Verdict: change to `available`
- Why: direct config-level receive-buffer size setter exists; the size-type difference is thin adaptation.

## 9. `SSL_CTX_set_num_tickets`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2222), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4767)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L81), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L402)
- Verdict: change to `available`
- Why: both directly set the configured number of TLS 1.3 session tickets.

## 10. `SSL_CTX_set_verify_depth`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1730), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3569)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L178), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L1059)
- Verdict: change to `available`
- Why: openHiTLS has a public macro-level setter for verification depth with matching purpose.

## Batch 010 summary

Change to `available`:
- `SSL_CTX_set_alpn_protos`
- `SSL_CTX_set_alpn_select_cb`
- `SSL_CTX_set_cert_verify_callback`
- `SSL_CTX_set_default_read_buffer_len`
- `SSL_CTX_set_num_tickets`
- `SSL_CTX_set_verify_depth`

Keep `partial`:
- `SSL_CTX_set_cipher_list`
- `SSL_CTX_set_ciphersuites`
- `SSL_CTX_set_client_CA_list`
- `SSL_CTX_set_client_cert_cb`

Main observation:
- The remaining SSL config setters split into two groups very cleanly:
  - direct public setters with only thin type/return adaptation,
  - and OpenSSL-specific convenience APIs that rely on string DSLs or richer certificate-list abstractions.
