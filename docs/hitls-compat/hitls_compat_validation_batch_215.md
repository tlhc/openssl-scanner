# openHiTLS Compatibility Validation Batch 215

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `i2d_X509_*` typed wrapper residue previously hanging on coarse top-level generators:
  - `i2d_X509_ACERT`
  - `i2d_X509_ACERT_bio`
  - `i2d_X509_ACERT_fp`
  - `i2d_X509_ALGOR`
  - `i2d_X509_ALGORS`
  - `i2d_X509_ATTRIBUTE`
  - `i2d_X509_AUX`
  - `i2d_X509_CERT_AUX`
  - `i2d_X509_CINF`
  - `i2d_X509_CRL_INFO`
  - `i2d_X509_EXTENSION`
  - `i2d_X509_EXTENSIONS`
  - `i2d_X509_NAME`
  - `i2d_X509_NAME_ENTRY`
  - `i2d_X509_PUBKEY`
  - `i2d_X509_PUBKEY_bio`
  - `i2d_X509_PUBKEY_fp`
  - `i2d_X509_REQ_INFO`
  - `i2d_X509_REVOKED`
  - `i2d_X509_SIG`
  - `i2d_X509_VAL`

Status:
- completed

Initial evidence:
- OpenSSL exposes these as standalone ASN.1 typed object families through public declarations like:
  - `DECLARE_ASN1_FUNCTIONS(X509_ALGOR)`
  - `DECLARE_ASN1_FUNCTIONS(X509_VAL)`
  - `DECLARE_ASN1_FUNCTIONS(X509_PUBKEY)`
  - `DECLARE_ASN1_FUNCTIONS(X509_SIG)`
  - `DECLARE_ASN1_FUNCTIONS(X509_REQ_INFO)`
  - `DECLARE_ASN1_FUNCTIONS(X509_ATTRIBUTE)`
  - `DECLARE_ASN1_FUNCTIONS(X509_NAME)`
  - `DECLARE_ASN1_FUNCTIONS(X509_REVOKED)`
  - `DECLARE_ASN1_FUNCTIONS(X509_ACERT)`
- OpenSSL implementations also use these typed wrapper encoders directly in wrapper-specific call paths, for example:
  - `i2d_X509_NAME`
  - `i2d_X509_ALGOR`
  - `i2d_X509_ALGORS`
  - `i2d_X509_PUBKEY`
  - `i2d_X509_CRL_INFO`
  - `i2d_X509_REQ_INFO`
  - `i2d_X509_AUX`
- openHiTLS public installed headers expose top-level generators for:
  - certificate
  - CRL
  - CSR
- openHiTLS public installed headers do not expose a standalone encode family for these wrapper objects.
- openHiTLS source has internal structs like `HITLS_X509_ReqInfo` or `HITLS_X509_NameNode`, but they are internal implementation details or support pieces, not a public installed typed object encode surface.

Verdict:
- keep `available = 0`
- adjust to `partial = 0`
- adjust to `not_available = 21`

Reasoning boundary:
- These `i2d_X509_*` interfaces are wrapper-object encoders.
- The previous mapping was too coarse because it reused:
  - `HITLS_X509_CertGenBuff`
  - `HITLS_X509_CrlGenBuff`
  - `HITLS_X509_CsrGenBuff`
- That replacement path only covers top-level certificate / CRL / CSR objects.
- It does not provide a public encode path for standalone objects like:
  - `X509_NAME`
  - `X509_ALGOR`
  - `X509_PUBKEY`
  - `X509_SIG`
  - `X509_REQ_INFO`
  - `X509_REVOKED`
  - `X509_CRL_INFO`
  - `X509_ACERT`
- Practical replaceability therefore fails at the public object-model boundary, so the whole batch belongs in `not_available`.

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L522)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L524)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L526)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L551)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L557)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L561)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L569)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L608)
  - [x509_acert.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_acert.h.in#L36)
- OpenSSL typed-wrapper use sites:
  - [store_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/store/store_lib.c#L360)
  - [cms_dh.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cms/cms_dh.c#L316)
  - [cms_sd.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cms/cms_sd.c#L1549)
  - [x_x509.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_x509.c#L254)
  - [x509_req.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_req.c#L349)
  - [x509cset.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509cset.c#L184)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L697)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L718)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L906)
- openHiTLS public installed encode surface:
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L283)
  - [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L150)
  - [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L85)
- openHiTLS internal-only residue examples:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L221)
  - [hitls_csr_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_csr/include/hitls_csr_local.h#L31)
  - [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L60)

Batch 215 inventory:
- total interfaces: `21`
- `not_available = 21`
