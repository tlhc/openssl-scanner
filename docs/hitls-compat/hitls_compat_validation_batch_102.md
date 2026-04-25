# openHiTLS Compatibility Validation Batch 102

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ADMISSION_SYNTAX_free`
- `ADMISSION_SYNTAX_get0_admissionAuthority`
- `ADMISSION_SYNTAX_get0_contentsOfAdmissions`
- `ADMISSION_SYNTAX_it`
- `ADMISSION_SYNTAX_new`
- `ADMISSION_SYNTAX_set0_admissionAuthority`
- `ADMISSION_SYNTAX_set0_contentsOfAdmissions`

Status:
- completed

Initial evidence:
- OpenSSL exposes `ADMISSION_SYNTAX` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L955), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L959), and its getters/setters in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L979).
- OpenSSL implements the ASN.1 type and accessors in [v3_admis.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_admis.c#L43), [v3_admis.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_admis.c#L51), and [v3_admis.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_admis.c#L240).
- openHiTLS public extension support does not expose any admission-syntax typed API; its public extension control surface is limited to selected extension getters in [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1380).

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public typed `ADMISSION_SYNTAX` object family or getters/setters.
