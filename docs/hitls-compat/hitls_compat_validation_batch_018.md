# openHiTLS Compatibility Validation Batch 018

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_connect`
- `SSL_accept`
- `SSL_do_handshake`
- `SSL_read_ex`
- `SSL_write_ex`
- `SSL_shutdown`
- `SSL_pending`
- `SSL_peek`
- `SSL_want`

Status:
- completed

## 1. `SSL_connect`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1886), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1752)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L129), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L352)
- Verdict: keep `partial`
- Why: same role, but return semantics differ (`1/0/-1` vs `HITLS_SUCCESS/error code`).

## 2. `SSL_accept`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1884), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1742)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L162), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L383)
- Verdict: keep `partial`
- Why: same reason as `SSL_connect`.

## 3. `SSL_do_handshake`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1993), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L3915)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L849), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L742)
- Verdict: keep `partial`
- Why: openHiTLS expects the endpoint to have been set previously, while OpenSSL will reuse the current handshake function and state.

## 4. `SSL_read_ex`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1888), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1897)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L200), [conn_read.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_read.c#L493)
- Verdict: keep `partial`
- Why: both use an out-parameter for bytes read, but OpenSSL still returns `1/0`, while openHiTLS returns status codes.

## 5. `SSL_write_ex`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1901), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L2151)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L234), [conn_write.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_write.c#L207)
- Verdict: keep `partial`
- Why: same mismatch profile as `SSL_read_ex`.

## 6. `SSL_shutdown`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2000), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L2231)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L284), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L476)
- Verdict: keep `partial`
- Why: OpenSSL’s bidirectional shutdown return semantics are richer than openHiTLS `HITLS_Close`.

## 7. `SSL_pending`
- Current JSON maps to `HITLS_GetReadPendingBytes`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1566), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1532)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L465), [conn_read.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_read.c#L537)
- Verdict: change to `available`
- Why: both directly return the number of currently readable pending application bytes.

## 8. `SSL_peek`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1896), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1993)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L216), [conn_read.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_read.c#L515)
- Verdict: keep `partial`
- Why: openHiTLS returns status + outparam rather than count directly.

## 9. `SSL_want`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1541), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4559)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1201), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L240)
- Verdict: keep `partial`
- Why: openHiTLS exposes rwstate via status + outparam, and the value space is not the same as OpenSSL `SSL_want()`’s enum set.

## Batch 018 summary

Change to `available`:
- `SSL_pending`

Keep `partial`:
- `SSL_connect`
- `SSL_accept`
- `SSL_do_handshake`
- `SSL_read_ex`
- `SSL_write_ex`
- `SSL_shutdown`
- `SSL_peek`
- `SSL_want`

Main observation:
- The main mismatch in this family is return/error model, not missing core TLS I/O functionality.
