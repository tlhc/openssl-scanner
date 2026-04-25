# openHiTLS Compatibility Validation Batch 204

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining high-value typed `d2i_*` object families outside the generic `d2i_ASN1_*` batch:
  - `PKCS7`
  - `PKCS8`
  - `X509_SIG`
  - `OCSP`
  - `TS`
  - `GENERAL_*`
  - `NETSCAPE_*`
  - `ESS_*`
  - `X509_*` typed wrappers still lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes many typed `d2i_*` helpers that decode DER into concrete wrapper objects such as:
  - `PKCS7 *`
  - `PKCS8_PRIV_KEY_INFO *`
  - `X509_SIG *`
  - `OCSP_*`
  - `TS_*`
  - `GENERAL_NAME *`
  - `NETSCAPE_SPKI *`
- openHiTLS public installed headers expose only a narrower set of functional parse/decode surfaces:
  - `HITLS_CMS_ProviderParseBuff/File`
  - `CRYPT_EAL_DecodeBuffKey`
  - `CRYPT_EAL_DecodeFileKey`
- Those public surfaces return `HITLS_CMS` or `CRYPT_EAL_PkeyCtx`, not the OpenSSL typed wrapper objects themselves.

Verdict:
- keep `available = 0`
- adjust to `partial = 7`
- adjust to `not_available = 73`

Reasoning boundary:
- `partial` is limited to the few entries where openHiTLS has a practical public parse/decode path for the underlying payload:
  - `d2i_PKCS7`
  - `d2i_PKCS7_bio`
  - `d2i_PKCS7_fp`
  - `d2i_PKCS8_PRIV_KEY_INFO`
  - `d2i_PKCS8_PRIV_KEY_INFO_bio`
  - `d2i_PKCS8_PRIV_KEY_INFO_fp`
  - `d2i_X509_SIG`
- `not_available` covers the remaining typed object families because openHiTLS does not expose public object-model replacements for them:
  - `OCSP_*`
  - `TS_*`
  - `GENERAL_NAME(S)`
  - `NETSCAPE_*`
  - `ESS_*`
  - various `X509_*` typed wrappers such as `X509_ALGOR`, `X509_ATTRIBUTE`, `X509_NAME`, `X509_REVOKED`, and related typed containers
- The shared blocker is the same across the whole batch:
  - parsing primitives exist in some areas
  - public typed wrapper-object replacement paths do not
