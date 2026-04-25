# openHiTLS Compatibility Validation Batch 199

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `X509_REQ_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a large CSR surface across:
  - `include/openssl/x509.h.in`
  - `crypto/x509/x_req.c`
  - `crypto/x509/x509_req.c`
  - `crypto/x509/x509rset.c`
  - `crypto/x509/t_req.c`
  - `crypto/x509/x_all.c`
- openHiTLS public installed headers expose a narrower CSR surface through:
  - `HITLS_X509_CsrNew`
  - `HITLS_X509_ProviderCsrNew`
  - `HITLS_X509_CsrFree`
  - `HITLS_X509_CsrCtrl`
  - `HITLS_X509_CsrParseBuff`
  - `HITLS_X509_CsrParseFile`
  - `HITLS_X509_CsrGenBuff`
  - `HITLS_X509_CsrGenFile`
  - `HITLS_X509_CsrSign`
  - `HITLS_X509_CsrVerify`
  - `HITLS_X509_AttrCtrl`
  - `HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_CSR)`

Verdict:
- keep `available = 0`
- adjust to `partial = 16`
- adjust to `not_available = 30`

Reasoning boundary:
- `partial` is limited to the CSR helpers that still have a practical public replacement path:
  - requested-extensions handling via `HITLS_X509_CsrCtrl(HITLS_X509_CSR_GET_ATTRIBUTES)` plus `HITLS_X509_AttrCtrl`
  - digest and dup through public encode-and-hash or encode-and-parse composition
  - public key, subject DN, signature-algorithm, provider-aware creation, print, pubkey set, subject-name construction, and signing through direct CSR APIs or command-dispatch composition
- `not_available` covers the OpenSSL-only layers that openHiTLS does not expose publicly:
  - ASN.1 item helpers such as `X509_REQ_it` and `X509_REQ_INFO_*`
  - generic `X509_ATTRIBUTE` object insertion, deletion, enumeration, and attribute-by-NID/OBJ/TXT helpers
  - raw signature and distinguishing-id setters/getters
  - version helpers
  - `sign_ctx`, `to_X509`, and caller-supplied-key `verify/verify_ex`
