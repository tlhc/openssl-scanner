# openHiTLS Compatibility Validation Batch 228

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `i2d_re_X509_*` TBS-only re-encode helpers lacking `analysis_doc`:
  - `i2d_re_X509_tbs`
  - `i2d_re_X509_REQ_tbs`
  - `i2d_re_X509_CRL_tbs`

Status:
- completed

Initial evidence:
- OpenSSL exposes explicit public helpers for re-encoding only the TBS section of:
  - certificate
  - CSR request info
  - CRL info
- Their implementations mark the cached encoded object as modified and then serialize:
  - `X509_CINF`
  - `X509_REQ_INFO`
  - `X509_CRL_INFO`
- openHiTLS public installed surface exposes only full-object encode paths:
  - `HITLS_X509_CertGenBuff`
  - `HITLS_X509_CrlGenBuff`
  - `HITLS_X509_CsrGenBuff`
  - plus `HITLS_X509_GET_ENCODELEN / HITLS_X509_GET_ENCODE`
- openHiTLS implementations do contain internal TBS encode steps such as:
  - `EncodeTbsCertificate`
  - `HITLS_X509_EncodeCrlTbsRaw`
  - `EncodeCsrReqInfo`
- but these are internal-only and not a public installed entrypoint.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 3`

Reasoning boundary:
- All 3 interfaces remain `not_available`.
- openHiTLS can encode the full certificate / CSR / CRL object.
- That does not create a public TBS-only encode helper.
- Practical replaceability fails because the OpenSSL APIs are specifically about re-encoding the mutable TBS layer, and openHiTLS does not publish that layer as a standalone encode surface.

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L584)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L711)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L769)
- OpenSSL implementations:
  - [x_x509.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_x509.c#L281)
  - [x509_req.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_req.c#L342)
  - [x509cset.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509cset.c#L181)
- openHiTLS public full-object encode surface:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L52)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L53)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L283)
  - [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L150)
  - [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L85)
- openHiTLS internal-only TBS encode steps:
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L903)
  - [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L536)
  - [hitls_x509_csr.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_csr/src/hitls_x509_csr.c#L445)

Batch 228 inventory:
- total interfaces: `3`
- `not_available = 3`
