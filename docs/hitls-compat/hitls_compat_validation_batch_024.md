# openHiTLS Compatibility Validation Batch 024

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_SESSION_get0_alpn_selected`
- `SSL_SESSION_set1_alpn_selected`
- `SSL_SESSION_get0_ticket`
- `SSL_SESSION_get_ticket_lifetime_hint`
- `SSL_SESSION_get_time`
- `SSL_SESSION_set_time`
- `SSL_SESSION_get0_peer`
- `SSL_SESSION_get0_hostname`
- `SSL_SESSION_set1_hostname`

Status:
- completed

Initial evidence:
- OpenSSL exposes this family as true session-object accessors in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1656) and implements them by directly reading or writing `SSL_SESSION` fields in [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L923).
- openHiTLS public session APIs in [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481) stop at lifecycle, protocol/cipher, timeout, session-id, ticket-presence, and user-data helpers.
- The missing accessors do exist internally as `SESS_*` helpers in [session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/session.h#L45) and [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L338), but that internal layer is outside the public truth-library boundary.

## 1. `SSL_SESSION_get0_alpn_selected`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1665), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1019)
- openHiTLS public/internal evidence: [hitls_alpn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_alpn.h#L109), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L430), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481)
- Verdict: keep `not_available`
- Why: openHiTLS only exposes negotiated ALPN on `HITLS_Ctx`, not on `HITLS_Session`, and there is no internal `SESS_GetAlpn*` accessor to bridge that gap.

## 2. `SSL_SESSION_set1_alpn_selected`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1668), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1027)
- openHiTLS public/internal evidence: [hitls_alpn.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_alpn.h#L97), [conn_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_common.c#L361), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481)
- Verdict: keep `not_available`
- Why: openHiTLS lets callers set ALPN proposals on `HITLS_Ctx` or `HITLS_Config`, but not on a session object, so there is no session-scoped public replacement.

## 3. `SSL_SESSION_get0_ticket`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1675), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L999)
- openHiTLS public/internal evidence: [session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/session.h#L51), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L633), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481)
- Verdict: keep `not_available`
- Why: `SESS_GetTicket()` exists, but it is internal-only. The installed public session API only exposes the boolean `HITLS_SESS_HasTicket`.

## 4. `SSL_SESSION_get_ticket_lifetime_hint`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1674), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L994)
- openHiTLS public/internal evidence: [session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/session.h#L68), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L694), [session_type.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session_type.h#L86)
- Verdict: keep `not_available`
- Why: openHiTLS internally stores `ticketAgeAdd`, not OpenSSL's ticket lifetime hint, and does not export either value through a public session API.

## 5. `SSL_SESSION_get_time`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1656), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L923)
- openHiTLS public/internal evidence: [session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/session.h#L62), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L466), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481)
- Verdict: keep `not_available`
- Why: `SESS_GetStartTime()` exists only in the internal session layer. No installed public accessor returns session creation/start time.

## 6. `SSL_SESSION_set_time`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1657), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L930)
- openHiTLS public/internal evidence: [session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/session.h#L64), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L481), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481)
- Verdict: keep `not_available`
- Why: `SESS_SetStartTime()` is likewise internal-only; the public session API has no setter for start time.

## 7. `SSL_SESSION_get0_peer`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1681), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L1046)
- openHiTLS public/internal evidence: [session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/session.h#L45), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L451), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L448), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L177)
- Verdict: keep `not_available`
- Why: openHiTLS has an internal `SESS_GetPeerCert()` and a public context-scoped `HITLS_GetPeerCertificate()`, but no public session-scoped getter returning an X.509 object from `HITLS_Session`.

## 8. `SSL_SESSION_get0_hostname`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1663), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L972)
- openHiTLS public/internal evidence: [session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/session.h#L57), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L362), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1308)
- Verdict: keep `not_available`
- Why: `SESS_GetHostName()` is internal-only. The public `HITLS_GetPeerName` path is verification-result oriented and context-scoped, not a session-hostname accessor.

## 9. `SSL_SESSION_set1_hostname`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1664), [ssl_sess.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_sess.c#L977)
- openHiTLS public/internal evidence: [session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/session.h#L54), [session.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/feature/session/src/session.c#L338), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1264)
- Verdict: keep `not_available`
- Why: `SESS_SetHostName()` exists only internally. Public `HITLS_SetHost` configures verification parameters on a live context, not a reusable session object.

## Batch 024 summary

Keep `not_available`:
- `SSL_SESSION_get0_alpn_selected`
- `SSL_SESSION_set1_alpn_selected`
- `SSL_SESSION_get0_ticket`
- `SSL_SESSION_get_ticket_lifetime_hint`
- `SSL_SESSION_get_time`
- `SSL_SESSION_set_time`
- `SSL_SESSION_get0_peer`
- `SSL_SESSION_get0_hostname`
- `SSL_SESSION_set1_hostname`

Main observation:
- This batch is the clearest illustration of the truth-library boundary.
- openHiTLS session internals are richer than the installed public surface, but internal `SESS_*` helpers do not count as compatibility.
