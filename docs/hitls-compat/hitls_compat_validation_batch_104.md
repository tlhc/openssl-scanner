# openHiTLS Compatibility Validation Batch 104

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `AUTHORITY_INFO_ACCESS_free`
- `AUTHORITY_INFO_ACCESS_it`
- `AUTHORITY_INFO_ACCESS_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `AUTHORITY_INFO_ACCESS` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L183) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L593), with ASN.1/template support in [v3_info.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_info.c#L55) and [v3_info.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_info.c#L59).
- openHiTLS public extension support does not expose any public typed AIA object family; its public extension control surface covers only selected extension getters such as AKI, BCONS, SAN, and generic extension retrieval in [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1380).

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public typed `AUTHORITY_INFO_ACCESS` object family.
