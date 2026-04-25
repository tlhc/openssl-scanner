# openHiTLS Compatibility Validation Batch 232

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `X509v3 general-name / distribution-point wrappers` lacking `analysis_doc`:
  - `i2d_GENERAL_NAME`
  - `i2d_GENERAL_NAMES`
  - `i2d_CRL_DIST_POINTS`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone wrapper-object families for:
  - `GENERAL_NAME`
  - `GENERAL_NAMES`
  - `CRL_DIST_POINTS`
  - along with related `DIST_POINT` / `DIST_POINT_NAME`
- openHiTLS public installed PKI surface exposes:
  - `HITLS_X509_GeneralName`
  - `HITLS_X509_ExtCtrl`
  - `HITLS_X509_FreeGeneralName`
- openHiTLS internal X509 extension code provides parsing and set-on-extension helpers:
  - `HITLS_X509_ParseGeneralNames`
  - `HITLS_X509_SetGeneralNames`
  - `SetExtGeneralNames`
- Those helpers operate on extension-owned data attached to cert/crl/csr objects.
- openHiTLS public installed headers do not expose standalone encode entrypoints for:
  - `GENERAL_NAME`
  - `GENERAL_NAMES`
  - `CRL_DIST_POINTS`

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 3`

Reasoning boundary:
- All 3 interfaces remain `not_available`.
- openHiTLS can manage general-name style data when it is owned by an X.509 extension object.
- That does not provide a public standalone wrapper encoder for OpenSSL `GENERAL_NAME`, `GENERAL_NAMES`, or `CRL_DIST_POINTS`.
- Practical replaceability fails at the public object-model boundary.

Representative evidence:
- OpenSSL declarations:
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L570)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L592)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L626)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L627)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L628)
- OpenSSL implementation evidence:
  - [v3_genn.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_genn.c#L55)
- openHiTLS public declarations:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L104)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L144)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L66)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L100)
- openHiTLS implementation evidence:
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L369)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L943)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1214)
  - [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L1339)

Batch 232 inventory:
- total interfaces: `3`
- `not_available = 3`
