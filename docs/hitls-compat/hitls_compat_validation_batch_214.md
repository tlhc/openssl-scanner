# openHiTLS Compatibility Validation Batch 214

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- top-level `i2d_*` encode family with a clear public openHiTLS encode surface:
  - `i2d_PKCS12`
  - `i2d_PKCS12_bio`
  - `i2d_PKCS12_fp`
  - `i2d_X509`
  - `i2d_X509_bio`
  - `i2d_X509_fp`
  - `i2d_X509_CRL`
  - `i2d_X509_CRL_bio`
  - `i2d_X509_CRL_fp`
  - `i2d_X509_REQ`
  - `i2d_X509_REQ_bio`
  - `i2d_X509_REQ_fp`

Status:
- completed

Initial evidence:
- OpenSSL exposes DER encoders for top-level PKI containers through:
  - `DECLARE_ASN1_FUNCTIONS(PKCS12)`
  - `DECLARE_ASN1_FUNCTIONS(X509)`
  - `DECLARE_ASN1_FUNCTIONS(X509_CRL)`
  - `DECLARE_ASN1_FUNCTIONS(X509_REQ)`
  - plus `_bio` / `_fp` wrappers in installed headers and `crypto/x509/x_all.c` or `crypto/pkcs12/p12_utl.c`
- openHiTLS exposes public ASN.1 buffer generators for the same top-level object families:
  - `HITLS_PKCS12_GenBuff`
  - `HITLS_X509_CertGenBuff`
  - `HITLS_X509_CrlGenBuff`
  - `HITLS_X509_CsrGenBuff`
- openHiTLS does not expose OpenSSL-shaped `BIO *` / `FILE *` writer helpers, and it does not preserve the `unsigned char **pp` cursor contract of raw `i2d_*`.

Verdict:
- keep `available = 0`
- keep `partial = 12`
- keep `not_available = 0`

Reasoning boundary:
- `partial` is correct for the whole batch because the practical encoding capability exists publicly, but the object and I/O contracts differ:
  - `i2d_PKCS12` -> `HITLS_PKCS12_GenBuff`
  - `i2d_X509` -> `HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1)`
  - `i2d_X509_CRL` -> `HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1)`
  - `i2d_X509_REQ` -> `HITLS_X509_CsrGenBuff(BSL_FORMAT_ASN1)`
  - `_bio` / `_fp` wrappers remain `partial` because openHiTLS returns encoded buffers rather than writing through OpenSSL `BIO *` or `FILE *`
- none of these should be raised to `available`:
  - raw `i2d_*` in OpenSSL is a cursor-style serializer over OpenSSL object types
  - openHiTLS public APIs are buffer-generation APIs over openHiTLS object types

Representative evidence:
- OpenSSL declarations:
  - [pkcs12.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs12.h.in#L294)
  - [pkcs12.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs12.h.in#L340)
  - [pkcs12.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs12.h.in#L342)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L558)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L574)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L610)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L383)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L385)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L387)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L431)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L433)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L435)
- OpenSSL implementations:
  - [p12_utl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs12/p12_utl.c#L235)
  - [p12_utl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs12/p12_utl.c#L241)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L261)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L272)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L283)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L294)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L351)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L370)
- openHiTLS declarations:
  - [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L209)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L283)
  - [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L150)
  - [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L85)
- openHiTLS implementations:
  - [hitls_pkcs12_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/pkcs12/src/hitls_pkcs12_common.c#L1619)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1059)
  - [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L742)
  - [hitls_x509_csr.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_csr/src/hitls_x509_csr.c#L577)

Batch 214 inventory:
- total interfaces: `12`
- `partial = 12`
