# openHiTLS Compatibility Validation Batch 225

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `ESS signing wrappers` lacking `analysis_doc`:
  - `i2d_ESS_CERT_ID`
  - `i2d_ESS_CERT_ID_V2`
  - `i2d_ESS_ISSUER_SERIAL`
  - `i2d_ESS_SIGNING_CERT`
  - `i2d_ESS_SIGNING_CERT_V2`

Status:
- completed

Initial evidence:
- OpenSSL exposes public `ESS_*` object families and encoders:
  - `ESS_ISSUER_SERIAL`
  - `ESS_CERT_ID`
  - `ESS_SIGNING_CERT`
  - `ESS_CERT_ID_V2`
  - `ESS_SIGNING_CERT_V2`
- OpenSSL also uses these encoders directly in timestamp response signing paths.
- openHiTLS public installed tree does not expose any `ESS_*` object family or encode helper.
- The only adjacent traces in openHiTLS are unrelated certificate/session processing and critical-extension handling, not ESS signing wrapper support.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 5`

Reasoning boundary:
- All 5 interfaces remain `not_available`.
- OpenSSL side is a standalone ESS wrapper-object encode family.
- openHiTLS public installed headers do not provide:
  - `ESS_CERT_ID` / `ESS_ISSUER_SERIAL` objects
  - `ESS_SIGNING_CERT` / `ESS_SIGNING_CERT_V2` objects
  - public encode helpers for ESS signing wrappers
- Practical replaceability therefore fails at the public object-model boundary.

Representative evidence:
- OpenSSL declarations:
  - [ess.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ess.h.in#L51)
  - [ess.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ess.h.in#L55)
  - [ess.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ess.h.in#L59)
  - [ess.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ess.h.in#L62)
  - [ess.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ess.h.in#L66)
- OpenSSL implementation evidence:
  - [ess_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ess/ess_asn1.c#L19)
  - [ess_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ess/ess_asn1.c#L27)
  - [ess_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ess/ess_asn1.c#L35)
  - [ess_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ess/ess_asn1.c#L43)
  - [ess_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ess/ess_asn1.c#L52)
  - [ts_rsp_sign.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_rsp_sign.c#L639)
  - [ts_rsp_sign.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_rsp_sign.c#L670)
- openHiTLS absence / adjacent-only evidence:
  - [hitls_pki_errno.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_errno.h#L86)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L481)

Batch 225 inventory:
- total interfaces: `5`
- `not_available = 5`
