# openHiTLS Compatibility Validation Batch 233

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `misc protocol/session wrappers` lacking `analysis_doc`:
  - `i2d_ISSUER_SIGN_TOOL`
  - `i2d_SCT_LIST`
  - `i2d_SXNET`
  - `i2d_SXNETID`
  - `i2d_SSL_SESSION`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone wrapper/object encoders for:
  - `ISSUER_SIGN_TOOL`
  - `SCT_LIST`
  - `SXNET`
  - `SXNETID`
  - `SSL_SESSION`
- openHiTLS public installed tree has no matching public object family or encode helper for:
  - SCT list
  - SXNET / SXNETID
  - issuer-sign tool wrappers
- openHiTLS does expose a public `HITLS_Session` object API:
  - `HITLS_SESS_New`
  - `HITLS_SESS_Dup`
  - `HITLS_SESS_Free`
  - getters/setters for fields like protocol version, cipher suite, session id, timeout
- but there is no public installed DER/ASN.1 encode helper for session objects.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 5`

Reasoning boundary:
- All 5 interfaces remain `not_available`.
- For `SSL_SESSION`, openHiTLS provides a manipulable session object but no public equivalent of `i2d_SSL_SESSION`.
- For `SCT_LIST`, `SXNET`, `SXNETID`, and `ISSUER_SIGN_TOOL`, there is no public installed object family or encode surface at all.
- Practical replaceability therefore fails at the public object-model/encode boundary.

Representative evidence:
- OpenSSL declarations:
  - [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L1182)
  - [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L1779)
  - [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L1793)
  - [ct.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ct.h.in#L386)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L551)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L552)
- OpenSSL implementation evidence:
  - [ct_oct.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ct/ct_oct.c#L391)
- openHiTLS public session surface:
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L489)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L498)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L510)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L542)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L656)
- openHiTLS adjacent-only evidence:
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L509)

Batch 233 inventory:
- total interfaces: `5`
- `not_available = 5`
