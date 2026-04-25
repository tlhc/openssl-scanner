# openHiTLS Compatibility Validation Batch 014

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_set_quiet_shutdown`
- `SSL_set_shutdown`
- `SSL_set_read_ahead`
- `SSL_get_read_ahead`
- `SSL_set_num_tickets`
- `SSL_get_rbio`
- `SSL_get_wbio`
- `SSL_set_rfd`
- `SSL_set_wfd`

Status:
- completed

Initial evidence:
- OpenSSL declarations and implementations are in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1565), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1570), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1576), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2053), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2220), and [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1330), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1404), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1434), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1522), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4280), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4755).
- openHiTLS counterparts are concentrated in [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L78), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L90), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L99), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L303), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L990), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L103), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1609), with implementations in [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L234), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L287), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L199), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L252), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L538), and [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1322).
- The main open questions are whether the setter/getter pairs are already direct enough for `available`, and how much the single-UIO model changes the verdict for `SSL_get_rbio` / `SSL_get_wbio` / `SSL_set_rfd`.

## 1. `SSL_set_quiet_shutdown`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2053), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4280)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L990), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L199)
- Verdict: change to `available`
- Why: direct public setter for the quiet-shutdown mode; status return is thin adaptation only.

## 2. `SSL_set_shutdown`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2055), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4290)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L303), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L252)
- Verdict: change to `available`
- Why: direct public setter for the shutdown-state bitfield.

## 3. `SSL_set_read_ahead`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1581), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1522)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1609), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1322)
- Verdict: keep `partial`
- Why: openHiTLS only exposes this as a config-level setter, not a direct per-connection setter.

## 4. `SSL_get_read_ahead`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1565), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1527)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1620), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1333)
- Verdict: keep `partial`
- Why: same reason as `SSL_set_read_ahead`.

## 5. `SSL_set_num_tickets`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2220), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4755)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L103), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L538)
- Verdict: change to `available`
- Why: direct public setter for the TLS 1.3 ticket count exists on the connection object.

## 6. `SSL_get_rbio`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1576), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1330)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L99), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L347)
- Verdict: keep `partial`
- Why: openHiTLS exposes a unified `BSL_UIO` handle rather than separate read/write BIOs.

## 7. `SSL_get_wbio`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1577), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1335)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L99), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L347)
- Verdict: keep `partial`
- Why: same single-UIO mismatch as `SSL_get_rbio`.

## 8. `SSL_set_rfd`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1570), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1434)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L90), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L234)
- Verdict: keep `partial`
- Why: openHiTLS can set a separate read UIO, but not directly from a file descriptor.

## 9. `SSL_set_wfd`
- Current JSON: `not_available`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1571), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1404)
- openHiTLS closest public APIs: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L78), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L90)
- Verdict: keep `not_available`
- Why: openHiTLS has no direct separate write-UIO setter from a file descriptor. `HITLS_SetUio` sets the unified transport handle instead.

## Batch 014 summary

Change to `available`:
- `SSL_set_quiet_shutdown`
- `SSL_set_shutdown`
- `SSL_set_num_tickets`

Keep `partial`:
- `SSL_set_read_ahead`
- `SSL_get_read_ahead`
- `SSL_get_rbio`
- `SSL_get_wbio`
- `SSL_set_rfd`

Keep `not_available`:
- `SSL_set_wfd`

Main observation:
- Setter/getter coverage is decent, but the unified UIO model is the key structural difference from OpenSSL’s split rbio/wbio abstraction.
