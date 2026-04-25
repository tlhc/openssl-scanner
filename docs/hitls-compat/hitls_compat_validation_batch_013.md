# openHiTLS Compatibility Validation Batch 013

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_get_client_random`
- `SSL_get_server_random`
- `SSL_get_servername`
- `SSL_get_servername_type`
- `SSL_get_security_callback`
- `SSL_set_security_callback`
- `SSL_get_security_level`
- `SSL_set_security_level`
- `SSL_get_info_callback`
- `SSL_CTX_set_info_callback`

Status:
- completed

Initial evidence:
- OpenSSL declarations live in [ssl.h](openssl-3.0.9/include/openssl/ssl.h) and are implemented across [ssl_lib.c](openssl-3.0.9/ssl/ssl_lib.c) and related runtime helpers.
- openHiTLS counterparts are concentrated in [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h), and [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c).
- The open questions are mostly about return conventions versus direct data getters, plus whether security/info callback setters are already public one-call equivalents.

## 1. `SSL_get_client_random`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2084), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4478)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L728), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L490)
- Verdict: keep `partial`
- Why: openHiTLS uses status + in/out length, while OpenSSL returns the copied length directly.

## 2. `SSL_get_server_random`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2086), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4488)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L728), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L490)
- Verdict: keep `partial`
- Why: same mismatch profile as `SSL_get_client_random`.

## 3. `SSL_get_servername`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L2838)
- openHiTLS declaration/implementation: [hitls_sni.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_sni.h#L55), [sni.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/sni/src/sni.c#L30)
- Verdict: change to `available`
- Why: direct public getter with matching `(ctx, type) -> const char *` shape.

## 4. `SSL_get_servername_type`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L2904)
- openHiTLS declaration/implementation: [hitls_sni.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_sni.h#L64), [sni.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/sni/src/sni.c#L82)
- Verdict: change to `available`
- Why: direct public getter with matching meaning and sentinel behavior.

## 5. `SSL_get_security_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2422), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4876)
- openHiTLS declaration/implementation: [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L139), [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L244), [security.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/security/src/security.c#L115)
- Verdict: change to `available`
- Why: direct public getter for the installed security callback.

## 6. `SSL_set_security_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2418), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4868)
- openHiTLS declaration/implementation: [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L235), [security.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/security/src/security.c#L105)
- Verdict: change to `available`
- Why: direct public setter for the security callback. Status return is thin adaptation only.

## 7. `SSL_get_security_level`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2417), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4863)
- openHiTLS declaration/implementation: [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L224), [security.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/security/src/security.c#L95)
- Verdict: keep `partial`
- Why: same integer value but openHiTLS returns status + outparam.

## 8. `SSL_set_security_level`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2416), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4858)
- openHiTLS declaration/implementation: [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L213), [security.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/security/src/security.c#L85)
- Verdict: change to `available`
- Why: direct public setter with only a status-return adaptation.

## 9. `SSL_get_info_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2076), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4462)
- openHiTLS declaration/implementation: [hitls_debug.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_debug.h#L68), [conn_debug.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_debug.c#L48)
- Verdict: change to `available`
- Why: direct public getter for the installed info callback.

## 10. `SSL_CTX_set_info_callback`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L721), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1315)
- openHiTLS declaration/implementation: [hitls_debug.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_debug.h#L79), [conn_debug.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_debug.c#L65)
- Verdict: change to `available`
- Why: direct public config-level setter for the info callback.

## Batch 013 summary

Change to `available`:
- `SSL_get_servername`
- `SSL_get_servername_type`
- `SSL_get_security_callback`
- `SSL_set_security_callback`
- `SSL_set_security_level`
- `SSL_get_info_callback`
- `SSL_CTX_set_info_callback`

Keep `partial`:
- `SSL_get_client_random`
- `SSL_get_server_random`
- `SSL_get_security_level`

Main observation:
- This batch is mostly stronger than the old JSON suggested. The main reason items stay `partial` is the recurrent status-plus-outparam pattern on numeric getters.
