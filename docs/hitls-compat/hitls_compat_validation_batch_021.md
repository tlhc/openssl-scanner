# openHiTLS Compatibility Validation Batch 021

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_CTX_get_info_callback`
- `SSL_CTX_get_num_tickets`
- `SSL_CTX_get_options`
- `SSL_CTX_get_quiet_shutdown`
- `SSL_CTX_get_security_callback`
- `SSL_CTX_get_security_level`
- `SSL_CTX_get_timeout`
- `SSL_CTX_get_verify_depth`
- `SSL_CTX_get_verify_mode`

Status:
- completed

Initial evidence:
- OpenSSL declarations/implementations are in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L578), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L723), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1537), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1726), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2052), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2223), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2430), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2435), plus implementations in [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1085), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1321), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1495), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4275), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4774), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4898), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4911), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4930).
- openHiTLS public counterparts are in [hitls_debug.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_debug.h#L102), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L90), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1239), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1262), [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L162), [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L182), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L189), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L674), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L782), with implementations in [conn_debug.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_debug.c#L82), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L380), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L412), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L653), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1550), [security.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/security/src/security.c#L34), [security.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/security/src/security.c#L56), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L725), [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L737).
- Most of these look like straightforward getter pairs; the main likely sticking points are the verify-mode bitmask reconstruction and the status+outparam pattern on several numeric getters.

## 1. `SSL_CTX_get_info_callback`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L723), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1321)
- openHiTLS declaration/implementation: [hitls_debug.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_debug.h#L102), [conn_debug.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_debug.c#L82)
- Verdict: `available`

## 2. `SSL_CTX_get_num_tickets`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2223), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4774)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L90), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L412)
- Verdict: `available`

## 3. `SSL_CTX_get_options`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L578), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4930)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1239), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L653)
- Verdict: keep `partial`
- Why: openHiTLS returns status + outparam, and option vocabulary still differs.

## 4. `SSL_CTX_get_quiet_shutdown`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2052), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4275)
- openHiTLS declaration/implementation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1262), [config.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config.c#L1550)
- Verdict: keep `partial`
- Why: same boolean information, but openHiTLS uses status + outparam.

## 5. `SSL_CTX_get_security_callback`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2435), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4911)
- openHiTLS declaration/implementation: [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L182), [security.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/security/src/security.c#L56)
- Verdict: `available`

## 6. `SSL_CTX_get_security_level`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2430), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4898)
- openHiTLS declaration/implementation: [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L162), [security.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/security/src/security.c#L34)
- Verdict: keep `partial`
- Why: openHiTLS returns status + outparam.

## 7. `SSL_CTX_get_timeout`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1537), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1085)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L384), [config_feature.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_feature.c#L380)
- Verdict: keep `partial`
- Why: openHiTLS returns status + outparam, even though the semantic value is the same.

## 8. `SSL_CTX_get_verify_depth`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1727), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1500)
- openHiTLS declaration/implementation: [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L189)
- Verdict: keep `partial`
- Why: macro-level getter exists, but current mapping uses the lower-level store control idiom and still differs in API shape.

## 9. `SSL_CTX_get_verify_mode`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1726), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1495)
- openHiTLS declarations/implementations:
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L674)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L782)
  - [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L725)
  - [config_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_cert.c#L737)
- Verdict: keep `partial`
- Why: reconstructing OpenSSL’s verify-mode bitmask still requires multiple boolean getters.

## Batch 021 summary

Change to `available`:
- `SSL_CTX_get_info_callback`
- `SSL_CTX_get_num_tickets`
- `SSL_CTX_get_security_callback`

Keep `partial`:
- `SSL_CTX_get_options`
- `SSL_CTX_get_quiet_shutdown`
- `SSL_CTX_get_security_level`
- `SSL_CTX_get_timeout`
- `SSL_CTX_get_verify_depth`
- `SSL_CTX_get_verify_mode`

Main observation:
- This family is mostly limited by the openHiTLS pattern of status-plus-outparam getters rather than missing functionality.
