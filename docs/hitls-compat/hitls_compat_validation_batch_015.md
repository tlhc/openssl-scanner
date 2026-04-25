# openHiTLS Compatibility Validation Batch 015

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_get_psk_identity`
- `SSL_get_psk_identity_hint`
- `SSL_set_psk_client_callback`
- `SSL_set_psk_server_callback`
- `SSL_set_psk_use_session_callback`
- `SSL_set_psk_find_session_callback`
- `SSL_use_psk_identity_hint`
- `SSL_set_session_ticket_ext`
- `SSL_set_session_ticket_ext_cb`

Status:
- completed

## 1. `SSL_get_psk_identity`
- Current JSON: `not_available`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L834), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4607)
- openHiTLS evidence: no public getter found in [hitls_psk.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_psk.h)
- Verdict: keep `not_available`

## 2. `SSL_get_psk_identity_hint`
- Current JSON: `not_available`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L833), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4600)
- openHiTLS evidence: no public getter found in [hitls_psk.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_psk.h)
- Verdict: keep `not_available`

## 3. `SSL_set_psk_client_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L822), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4614)
- openHiTLS declaration/implementation: [hitls_psk.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_psk.h#L143), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L370)
- Verdict: change to `available`

## 4. `SSL_set_psk_server_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L829), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4624)
- openHiTLS declaration/implementation: [hitls_psk.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_psk.h#L154), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L378)
- Verdict: change to `available`

## 5. `SSL_set_psk_use_session_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L849), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4646)
- openHiTLS declaration/implementation: [hitls_psk.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_psk.h#L210), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L804)
- Verdict: change to `available`

## 6. `SSL_set_psk_find_session_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L846), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4635)
- openHiTLS declaration/implementation: [hitls_psk.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_psk.h#L199), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L795)
- Verdict: change to `available`

## 7. `SSL_use_psk_identity_hint`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L832), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4581)
- openHiTLS declaration/implementation: [hitls_psk.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_psk.h#L166), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L387), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1408)
- Verdict: change to `available`
- Why: direct setter exists; string vs `(uint8_t *, len)` is thin adaptation.

## 8. `SSL_set_session_ticket_ext`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2186), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1113)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L216), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L759)
- Verdict: change to `available`

## 9. `SSL_set_session_ticket_ext_cb`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2188), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1103)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L202), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L747)
- Verdict: change to `available`

## Batch 015 summary

Change to `available`:
- `SSL_set_psk_client_callback`
- `SSL_set_psk_server_callback`
- `SSL_set_psk_use_session_callback`
- `SSL_set_psk_find_session_callback`
- `SSL_use_psk_identity_hint`
- `SSL_set_session_ticket_ext`
- `SSL_set_session_ticket_ext_cb`

Keep `not_available`:
- `SSL_get_psk_identity`
- `SSL_get_psk_identity_hint`

Main observation:
- openHiTLS has strong public coverage for PSK and custom ticket setter/callback APIs.
- The remaining gap in this family is readback of negotiated/stored PSK identity strings.
