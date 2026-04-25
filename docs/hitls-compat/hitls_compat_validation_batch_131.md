# openHiTLS Compatibility Validation Batch 131

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SMIME_crlf_copy`
- `SMIME_read_ASN1`
- `SMIME_read_ASN1_ex`
- `SMIME_read_CMS`
- `SMIME_read_CMS_ex`
- `SMIME_read_PKCS7`
- `SMIME_read_PKCS7_ex`
- `SMIME_text`
- `SMIME_write_ASN1`
- `SMIME_write_ASN1_ex`
- `SMIME_write_CMS`
- `SMIME_write_PKCS7`

Status:
- completed

Initial evidence:
- OpenSSL publishes the S/MIME wrapper family in [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L929), [cms.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cms.h.in#L116), and [pkcs7.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/pkcs7.h.in#L347).
- OpenSSL implements MIME/SMIME parsing and wrapping in [asn_mime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn_mime.c#L238), [asn_mime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn_mime.c#L397), [asn_mime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn_mime.c#L512), [cms_io.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/cms/cms_io.c#L80), and [pk7_mime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/pkcs7/pk7_mime.c#L30).
- openHiTLS publicly exposes CMS parse/sign/verify only at the CMS payload layer in [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L72), [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L89), [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L110), and [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L127).
- openHiTLS does not expose public MIME boundary helpers such as CRLF canonicalization, MIME multipart extraction, text-mode S/MIME helpers, or `SMIME_*` wrappers over ASN.1/CMS/PKCS7 flows.
- Under the current replaceability rule, lower-layer CMS capability alone is insufficient because the OpenSSL `SMIME_*` APIs are developer-facing MIME/SMIME wrappers, and openHiTLS does not offer a practically substitutable public migration path for that surface.

Verdict:
- keep `not_available` for all entries in scope.
