# openHiTLS Compatibility Validation Batch 022

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_SESSION_free`
- `SSL_SESSION_dup`
- `SSL_SESSION_set1_id`
- `SSL_SESSION_get0_id_context`
- `SSL_SESSION_set1_id_context`
- `SSL_SESSION_get_timeout`
- `SSL_SESSION_set_timeout`
- `SSL_SESSION_get_protocol_version`
- `SSL_SESSION_set_protocol_version`

Status:
- completed

## 1. `SSL_SESSION_free`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1702), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L820)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L498), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L99)
- Verdict: `available`

## 2. `SSL_SESSION_dup`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1690), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L155)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L489), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L72)
- Verdict: keep `partial`
- Why: openHiTLS `HITLS_SESS_Dup()` increments the reference count and returns the same object, while OpenSSL `SSL_SESSION_dup()` produces a duplicate session object.

## 3. `SSL_SESSION_set1_id`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1685), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L883)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L611), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L286)
- Verdict: keep `partial`
- Why: same setter role, but openHiTLS rejects zero-length input and returns status codes instead of OpenSSL’s boolean.

## 4. `SSL_SESSION_get0_id_context`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1693), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L291)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L599), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L264)
- Verdict: keep `partial`
- Why: openHiTLS copies out into caller-owned storage instead of returning a direct pointer.

## 5. `SSL_SESSION_set1_id_context`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1682), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1051)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L587), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L240)
- Verdict: keep `partial`
- Why: same setter role, but openHiTLS requires non-null pointer even for zero-sized context and returns status codes.

## 6. `SSL_SESSION_get_timeout`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1658), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L916)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L666), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L510)
- Verdict: `available`

## 7. `SSL_SESSION_set_timeout`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1659), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L896)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L656), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L496)
- Verdict: keep `partial`
- Why: OpenSSL returns success/previous semantic boolean-ish `long`, while openHiTLS returns status code.

## 8. `SSL_SESSION_get_protocol_version`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1660), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L950)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L542), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L393)
- Verdict: keep `partial`
- Why: openHiTLS returns status + outparam.

## 9. `SSL_SESSION_set_protocol_version`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1661), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L955)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L553), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L379)
- Verdict: `available`
- Why: direct setter with only thin return-code adaptation.

## Batch 022 summary

Change to `available`:
- `SSL_SESSION_free`
- `SSL_SESSION_get_timeout`
- `SSL_SESSION_set_protocol_version`

Keep `partial`:
- `SSL_SESSION_dup`
- `SSL_SESSION_set1_id`
- `SSL_SESSION_get0_id_context`
- `SSL_SESSION_set1_id_context`
- `SSL_SESSION_set_timeout`
- `SSL_SESSION_get_protocol_version`

Main observation:
- The session-family remaining gaps are mostly about direct-pointer getters versus copy-out APIs, plus the fact that openHiTLS `Dup` is really an up-ref rather than a deep clone.
