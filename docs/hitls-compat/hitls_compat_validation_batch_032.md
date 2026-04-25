# openHiTLS Compatibility Validation Batch 032

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CTX_load_verify_locations`
- `SSL_CTX_use_PrivateKey_file`
- `SSL_CTX_use_PrivateKey`
- `TLS_server_method`
- `SSL_set_connect_state`

Status:
- completed

Initial evidence:
- This family is the next coherent high-frequency group without `analysis_doc`.
- Current scan aggregation shows:
  - `SSL_CTX_load_verify_locations`: 13 repos
  - `SSL_CTX_use_PrivateKey_file`: 11 repos
  - `SSL_CTX_use_PrivateKey`: 9 repos
  - `TLS_server_method`: 9 repos
  - `SSL_set_connect_state`: 9 repos
- The common pattern is config-level decomposition:
  - OpenSSL compresses method selection, verify-path loading, and key loading into coarse helpers
  - openHiTLS exposes smaller config-level public APIs that must be composed

## 1. `SSL_CTX_load_verify_locations`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2066), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4440)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1396), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1438), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L1126), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L1353)
- Verdict: change to `partial`
- Why: openHiTLS can load verify roots from file and directory through separate public APIs, but it does not provide the same one-call combined helper as OpenSSL.

## 2. `SSL_CTX_use_PrivateKey_file`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1628), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L354)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L473), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L392)
- Verdict: keep `partial`
- Why: openHiTLS can load a private key from file, but the parse-format and key object model differ from OpenSSL's `EVP_PKEY`-oriented API.

## 3. `SSL_CTX_use_PrivateKey`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1743), [ssl_rsa.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_rsa.c#L345)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L461), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L368)
- Verdict: keep `partial`
- Why: openHiTLS can set the config private key directly, but it operates on `HITLS_CERT_Key` rather than OpenSSL `EVP_PKEY`.

## 4. `TLS_server_method`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1938), [methods.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/methods.c#L51)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L437), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1684), [config_tls.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_tls.c#L81), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1656)
- Verdict: keep `partial`
- Why: openHiTLS does not expose `SSL_METHOD` objects. The closest public path is config construction plus explicit endpoint configuration.

## 5. `SSL_set_connect_state`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2028), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3952)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L140), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L296)
- Verdict: keep `partial`
- Why: OpenSSL only sets client-side state flags, while openHiTLS endpoint setup is a stricter public API that requires `CM_STATE_IDLE` and participates in connection setup semantics.

## Batch 032 summary

Change to `partial`:
- `SSL_CTX_load_verify_locations`

Keep `partial`:
- `SSL_CTX_use_PrivateKey_file`
- `SSL_CTX_use_PrivateKey`
- `TLS_server_method`
- `SSL_set_connect_state`

Main observation:
- This batch was previously too pessimistic in one place:
  - `SSL_CTX_load_verify_locations` is not missing functionality; it is split across `LoadVerifyFile + LoadVerifyDir`
- The rest stay `partial` because openHiTLS decomposes OpenSSL's coarse helpers into smaller config-level public APIs.
