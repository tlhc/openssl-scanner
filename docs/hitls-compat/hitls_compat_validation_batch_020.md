# openHiTLS Compatibility Validation Batch 020

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_get_verify_callback`
- `SSL_CTX_get_verify_callback`
- `SSL_CTX_get_client_cert_cb`
- `SSL_CTX_sess_get_get_cb`
- `SSL_CTX_sess_get_new_cb`
- `SSL_CTX_sess_get_remove_cb`
- `SSL_CTX_sess_set_get_cb`
- `SSL_CTX_sess_set_remove_cb`

Status:
- completed

## 1. `SSL_get_verify_callback`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1584), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1491)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L803), [conn_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_cert.c#L238)
- Verdict: `available`

## 2. `SSL_CTX_get_verify_callback`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1728), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1505)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L783), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L693)
- Verdict: `available`

## 3. `SSL_CTX_get_client_cert_cb`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L728), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1333)
- openHiTLS evidence: no public getter found for `HITLS_CFG_SetCertCb`
- Verdict: keep `not_available`

## 4. `SSL_CTX_sess_get_get_cb`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L718), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1308)
- openHiTLS evidence: no public getter found for `HITLS_CFG_SetSessionGetCb`
- Verdict: keep `not_available`

## 5. `SSL_CTX_sess_get_new_cb`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L704), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1285)
- openHiTLS evidence: no public getter found for `HITLS_CFG_SetNewSessionCb`
- Verdict: keep `not_available`

## 6. `SSL_CTX_sess_get_remove_cb`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L710), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1295)
- openHiTLS evidence: no public getter found for `HITLS_CFG_SetSessionRemoveCb`
- Verdict: keep `not_available`

## 7. `SSL_CTX_sess_set_get_cb`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L712), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1300)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L179), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L489)
- Verdict: `available`

## 8. `SSL_CTX_sess_set_remove_cb`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L706), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1289)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L190), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L499)
- Verdict: `available`

## Batch 020 summary

Change to `available`:
- `SSL_get_verify_callback`
- `SSL_CTX_get_verify_callback`
- `SSL_CTX_sess_set_get_cb`
- `SSL_CTX_sess_set_remove_cb`

Keep `not_available`:
- `SSL_CTX_get_client_cert_cb`
- `SSL_CTX_sess_get_get_cb`
- `SSL_CTX_sess_get_new_cb`
- `SSL_CTX_sess_get_remove_cb`

Main observation:
- openHiTLS has better public callback getter/setter coverage than the old JSON suggested for verification and session-cache setters.
- The remaining gap is getter symmetry: several OpenSSL callback getter APIs still have no public openHiTLS counterparts.
