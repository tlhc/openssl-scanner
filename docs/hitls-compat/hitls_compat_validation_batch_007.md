# openHiTLS Compatibility Validation Batch 007

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_new`
- `SSL_free`
- `SSL_get_error`
- `SSL_CTX_free`
- `SSL_CTX_get_cert_store`
- `TLS_client_method`
- `SSL_set_options`
- `SSL_CTX_set_options`
- `SSL_CTX_get_ex_data`
- `SSL_CTX_set_ex_data`
- `SSL_get_verify_result`
- `SSL_CTX_clear_options`
- `SSL_get0_alpn_selected`
- `SSL_get_SSL_CTX`
- `SSL_get_current_cipher`
- `SSL_CTX_set_verify`
- `SSL_CTX_set_cert_cb`
- `SSL_CTX_sess_set_new_cb`
- `SSL_SESSION_get_id`

Status:
- completed

Initial evidence:
- OpenSSL declarations are concentrated in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L580), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L701), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L805), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1535), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1691), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1729), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1768), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1867), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1915), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1939), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2072), and [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2081).
- Core openHiTLS runtime/config/session entry points are in:
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L43)
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L52)
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L637)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L437)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L503)
  - [hitls_error.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_error.h#L450)
  - [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L144)
  - [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L774)
  - [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L825)
  - [hitls_alpn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_alpn.h#L109)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L161)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L472)
- Current mapping baseline for this batch is uniformly `partial`, which means the main work here is to separate true public equivalence from over-compressed “directionally similar” entries.

Key questions for this batch:
- which `SSL_CTX`-level operations are genuinely one-call public replacements and which ones are actually multi-call config choreography,
- whether `SSL_get_error` / `SSL_get_verify_result` stay `partial` because their error/result models differ materially,
- and whether callback/ex-data style APIs should remain `partial` because openHiTLS exposes only single-pointer user data rather than OpenSSL’s indexed ex-data model.

## Direct public replacements

### `SSL_new`
- Current JSON: `partial`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L672)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L43), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L61)
- Verdict: change to `available`
- Why: both create a per-connection TLS object from a configuration object and retain the configuration by reference while populating per-connection state. The remaining difference is type naming plus openHiTLS's explicit config dump step, which is thin adaptation.

### `SSL_free`
- Current JSON: `partial`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1172)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L52), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L145)
- Verdict: change to `available`
- Why: both are public void destructors for the TLS connection object.

### `SSL_CTX_free`
- Current JSON: `partial`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3429)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L503), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L621)
- Verdict: change to `available`
- Why: both are public void destructors for the TLS configuration object.

### `SSL_CTX_get_cert_store`
- Current JSON: `partial`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4541)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L144), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L184)
- Verdict: change to `available`
- Why: openHiTLS has a direct config-level cert-store getter. The earlier note about verify/chain stores was overly broad for this specific interface.

### `SSL_CTX_set_cert_cb`
- Current JSON: `partial`
- OpenSSL declaration/docs: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1734), [SSL_CTX_set_cert_cb.3](openssl-3.0.9/doc/man/man3/SSL_CTX_set_cert_cb.3:70)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L943), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L704)
- openHiTLS retry semantics: [hitls_error.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_error.h#L91), [recv_client_hello.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/handshake/recv/src/recv_client_hello.c#L1392)
- Verdict: change to `available`
- Why: both APIs publicly register a certificate-selection callback of shape `(ctx_like, void *arg)`. Retry signaling differs, but that affects callback implementation details rather than the setter itself.

### `SSL_CTX_sess_set_new_cb`
- Current JSON: `partial`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L701)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L123), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L168), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L390)
- Verdict: change to `available`
- Why: both publicly register a new-session callback with a connection handle and session handle.

### `SSL_get_SSL_CTX`
- Current JSON: `partial`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4310)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L637), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L297)
- openHiTLS global-config getter evidence: [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L304)
- Verdict: change to `available`
- Why: `HITLS_GetGlobalConfig()` returns the original configuration object associated with the connection, which is the direct analogue of `SSL_get_SSL_CTX()`.

### `SSL_get_current_cipher`
- Current JSON: `partial`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4206)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L704), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L398)
- Verdict: change to `available`
- Why: both are direct getters for the negotiated cipher object.

## Keep `partial`

### `SSL_get_error`
- OpenSSL declaration/docs: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1915), [SSL_get_error.3](openssl-3.0.9/doc/man/man3/SSL_get_error.3:1)
- openHiTLS declaration/implementation: [hitls_error.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_error.h#L450), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L534)
- Verdict: keep `partial`
- Why: same purpose, different error taxonomy and retry-state mapping.

### `TLS_client_method`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1939)
- openHiTLS declarations: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L437), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1684)
- Verdict: keep `partial`
- Why: openHiTLS has config constructors plus endpoint setters, not a method object.

### `SSL_set_options`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L583)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1290), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L339)
- Verdict: keep `partial`
- Why: both set option bits, but return model and option vocabulary differ.

### `SSL_CTX_set_options`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L582)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1219), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L633)
- Verdict: keep `partial`
- Why: same reason as `SSL_set_options`.

### `SSL_CTX_get_ex_data`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4536)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1309), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1226)
- Verdict: keep `partial`
- Why: openHiTLS has only one user-data slot, not indexed `ex_data`.

### `SSL_CTX_set_ex_data`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4531)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1324), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1235)
- Verdict: keep `partial`
- Why: setter exists, but only for a single user-data pointer.

### `SSL_get_verify_result`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2081)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L825), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L155)
- Verdict: keep `partial`
- Why: OpenSSL returns the verify result directly; openHiTLS returns status and writes the verify result through an out parameter.

### `SSL_CTX_clear_options`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L580)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1229), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L643)
- Verdict: keep `partial`
- Why: same role, different return and bit vocabulary semantics.

### `SSL_get0_alpn_selected`
- OpenSSL implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3122)
- openHiTLS declaration/implementation: [hitls_alpn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_alpn.h#L109), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L430)
- Verdict: keep `partial`
- Why: both expose the selected ALPN protocol, but openHiTLS adds a status return and mutable pointer type.

### `SSL_CTX_set_verify`
- OpenSSL declaration: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1729)
- openHiTLS declarations/implementations:
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L599)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L615)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L771)
  - [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L774)
  - [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L684)
- Verdict: keep `partial`
- Why: OpenSSL packs verify-mode flags and callback into one API; openHiTLS splits them across multiple setters.

### `SSL_SESSION_get_id`
- OpenSSL implementation: [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L285)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L623), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L218)
- Verdict: keep `partial`
- Why: OpenSSL returns a pointer to internal session-id storage; openHiTLS copies the session ID into caller-provided memory.

## Batch 007 summary

Change to `available`:
- `SSL_new`
- `SSL_free`
- `SSL_CTX_free`
- `SSL_CTX_get_cert_store`
- `SSL_CTX_set_cert_cb`
- `SSL_CTX_sess_set_new_cb`
- `SSL_get_SSL_CTX`
- `SSL_get_current_cipher`

Keep `partial`:
- `SSL_get_error`
- `TLS_client_method`
- `SSL_set_options`
- `SSL_CTX_set_options`
- `SSL_CTX_get_ex_data`
- `SSL_CTX_set_ex_data`
- `SSL_get_verify_result`
- `SSL_CTX_clear_options`
- `SSL_get0_alpn_selected`
- `SSL_CTX_set_verify`
- `SSL_SESSION_get_id`

Main observation:
- openHiTLS is stronger than the previous JSON suggested for basic TLS object/config lifecycle and direct negotiated-state getters.
- The remaining gaps in this batch are mostly about composed configuration APIs, indexed `ex_data`, and value-return conventions rather than missing core functionality.
