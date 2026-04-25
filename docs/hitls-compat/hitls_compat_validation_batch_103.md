# openHiTLS Compatibility Validation Batch 103

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ADMISSIONS_free`
- `ADMISSIONS_get0_admissionAuthority`
- `ADMISSIONS_get0_namingAuthority`
- `ADMISSIONS_get0_professionInfos`
- `ADMISSIONS_it`
- `ADMISSIONS_new`
- `ADMISSIONS_set0_admissionAuthority`
- `ADMISSIONS_set0_namingAuthority`
- `ADMISSIONS_set0_professionInfos`

Status:
- completed

Initial evidence:
- OpenSSL exposes `ADMISSIONS` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L954), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L958), and its getters/setters in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L987).
- OpenSSL implements the ASN.1 type and accessors in [v3_admis.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_admis.c#L37), [v3_admis.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_admis.c#L50), and [v3_admis.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_admis.c#L264).
- openHiTLS public extension support does not expose any admissions typed API; its public extension control surface is limited to selected extension getters in [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1380).

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public typed `ADMISSIONS` object family or getters/setters.
