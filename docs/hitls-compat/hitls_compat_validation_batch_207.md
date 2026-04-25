# openHiTLS Compatibility Validation Batch 207

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `d2i_*` extension/value typed object family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes many typed wrapper families for X509v3 extension/value objects, for example in `x509v3.h.in`:
  - `ACCESS_DESCRIPTION`
  - `ADMISSIONS`
  - `ADMISSION_SYNTAX`
  - `AUTHORITY_INFO_ACCESS`
  - `AUTHORITY_KEYID`
  - `BASIC_CONSTRAINTS`
  - `CERTIFICATEPOLICIES`
  - `DIST_POINT`
  - `DIST_POINT_NAME`
  - `EXTENDED_KEY_USAGE`
  - `ISSUING_DIST_POINT`
  - `NAMING_AUTHORITY`
  - `POLICYINFO`
  - `POLICYQUALINFO`
  - `PROXY_CERT_INFO_EXTENSION`
  - `PROXY_POLICY`
  - `USERNOTICE`
- openHiTLS public installed headers expose typed extension control on parsed certificates/CRLs/CSRs and a few helper structs:
  - `HITLS_X509_ExtCtrl`
  - `HITLS_X509_EXT_GET/SET_AKI`
  - `HITLS_X509_EXT_GET/SET_BCONS`
  - `HITLS_X509_EXT_GET/SET_SAN`
  - `HITLS_X509_EXT_GET/SET_EXKUSAGE`
  - `HITLS_X509_EXT_GET/SET_GENERIC`
  - `HITLS_X509_ParseGeneralNames`
  - `HITLS_X509_ParseAuthorityKeyId`
- That public surface is extension-value oriented, not wrapper-object oriented.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 24`

Reasoning boundary:
- These `d2i_*` interfaces decode DER into concrete OpenSSL typed wrapper objects.
- openHiTLS gives developers typed extension getters/setters on owning certificate/CRL/CSR objects, and some internal or narrow parse helpers.
- It does not expose a public practical replacement path for the standalone wrapper-object decode surface itself.
- The whole batch therefore remains `not_available`.
