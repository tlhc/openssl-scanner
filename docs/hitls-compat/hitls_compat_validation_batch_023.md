# openHiTLS Compatibility Validation Batch 023

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_SESSION_new`
- `SSL_SESSION_get0_cipher`
- `SSL_SESSION_set_cipher`
- `SSL_SESSION_get_ex_data`
- `SSL_SESSION_set_ex_data`
- `SSL_SESSION_has_ticket`
- `SSL_SESSION_is_resumable`
- `SSL_SESSION_get_master_key`
- `SSL_SESSION_set1_master_key`

Status:
- completed

Initial evidence:
- OpenSSL session accessor declarations are in [ssl.h](openssl-3.0.9/include/openssl/ssl.h), with implementations in [ssl_sess.c](openssl-3.0.9/ssl/ssl_sess.c).
- openHiTLS public counterparts are concentrated in [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h) and implementations in [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c).
- Likely decision boundary:
  - direct session lifecycle / plain getters may be `available`
  - object-type mismatches such as `const SSL_CIPHER *` vs numeric cipher-suite IDs or single-slot user data vs indexed ex_data likely stay `partial`.

## 1. `SSL_SESSION_new`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1689), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L122)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L39)
- Verdict: `available`

## 2. `SSL_SESSION_get0_cipher`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1671), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L961)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L575), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L537)
- Verdict: keep `partial`
- Why: openHiTLS returns a numeric cipher-suite ID, not a `const SSL_CIPHER *`.

## 3. `SSL_SESSION_set_cipher`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1672), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L966)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L564), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L524)
- Verdict: keep `partial`
- Why: same setter role, but the cipher representation is numeric rather than an `SSL_CIPHER *`.

## 4. `SSL_SESSION_get_ex_data`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2101), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L117)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L694), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L707)
- Verdict: keep `partial`
- Why: openHiTLS only exposes a single user-data slot, not indexed ex_data.

## 5. `SSL_SESSION_set_ex_data`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2100), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L112)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L704), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L719)
- Verdict: keep `partial`
- Why: same single-slot vs indexed ex_data mismatch.

## 6. `SSL_SESSION_has_ticket`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1673), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L989)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L685), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L648)
- Verdict: `available`

## 7. `SSL_SESSION_is_resumable`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1687), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1065)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L676), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L196)
- Verdict: `available`
- Why: both perform a simple resumability predicate over enable/resumable state and session id/ticket presence.

## 8. `SSL_SESSION_get_master_key`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2088), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4498)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L531), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L588)
- Verdict: keep `partial`
- Why: openHiTLS uses status + outparam rather than returning the copied length directly.

## 9. `SSL_SESSION_set1_master_key`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2090), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4509)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L510), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L551)
- Verdict: `available`
- Why: direct setter exists and copies the master key into the session object.

## Batch 023 summary

Change to `available`:
- `SSL_SESSION_new`
- `SSL_SESSION_has_ticket`
- `SSL_SESSION_is_resumable`
- `SSL_SESSION_set1_master_key`

Keep `partial`:
- `SSL_SESSION_get0_cipher`
- `SSL_SESSION_set_cipher`
- `SSL_SESSION_get_ex_data`
- `SSL_SESSION_set_ex_data`
- `SSL_SESSION_get_master_key`

Main observation:
- The session object API is stronger than the old mapping suggested.
- The remaining partials are mostly about object-type mismatch (`SSL_CIPHER *`) or the recurring status-plus-outparam pattern.
