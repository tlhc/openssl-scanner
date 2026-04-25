# openHiTLS Compatibility Validation Batch 197

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `X509_CRL_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a broad `X509_CRL_*` family across:
  - `include/openssl/x509.h.in`
  - `crypto/x509/x_crl.c`
  - `crypto/x509/x509cset.c`
  - `crypto/x509/x509_ext.c`
  - `crypto/x509/t_crl.c`
  - `crypto/x509/x_all.c`
- openHiTLS public installed headers expose a narrower CRL surface through:
  - `HITLS_X509_CrlNew`
  - `HITLS_X509_CrlFree`
  - `HITLS_X509_CrlCtrl`
  - `HITLS_X509_CrlParseBuff`
  - `HITLS_X509_CrlParseFile`
  - `HITLS_X509_CrlGenBuff`
  - `HITLS_X509_CrlGenFile`
  - `HITLS_X509_CrlVerify`
  - `HITLS_X509_CrlSign`
  - `HITLS_X509_CrlEntryNew`
  - `HITLS_X509_CrlEntryCtrl`
  - `HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_CRL)`

Verdict:
- adjust to `available = 2`
- adjust to `partial = 22`
- adjust to `not_available = 28`

Reasoning boundary:
- `available` is limited to the direct CRL object lifecycle that openHiTLS exposes one-for-one: `X509_CRL_new` and `X509_CRL_free`.
- `partial` covers public composition paths that are practical but shaped differently, such as:
  - command-dispatch getters and setters through `HITLS_X509_CrlCtrl`
  - revoked-entry insertion through `HITLS_X509_CrlEntryNew/Ctrl` plus `HITLS_X509_CrlCtrl(HITLS_X509_CRL_ADD_REVOKED_CERT)`
  - encode-and-hash or encode-and-parse composition for `X509_CRL_digest` and `X509_CRL_dup`
  - CRL printing through `HITLS_PKI_PrintCtrl`
  - CRL signing through `HITLS_X509_CrlSign`
- `not_available` covers the OpenSSL-only surfaces that have no public openHiTLS analogue:
  - ASN.1 item helpers such as `X509_CRL_it` and `X509_CRL_INFO_*`
  - CRL method-object customization such as `X509_CRL_METHOD_*`, `set_default_method`, and meth-data helpers
  - generic extension-stack helpers such as `X509_CRL_get_ext*`, `X509_CRL_add_ext`, and `X509_CRL_delete_ext`
  - HTTP loading, Suite B checking, direct CRL diff/cmp/match helpers, and `sign_ctx`
