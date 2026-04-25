# openHiTLS Compatibility Validation Batch 101

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ACCESS_DESCRIPTION_free`
- `ACCESS_DESCRIPTION_it`
- `ACCESS_DESCRIPTION_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `ACCESS_DESCRIPTION` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L173) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L592), with ASN.1 implementation in [v3_info.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_info.c#L48) and [v3_info.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_info.c#L53).
- openHiTLS public X509 extension support covers selected extension getters such as AKI, basic constraints, SAN, and generic extension access in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L99) and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1380).
- There is no public openHiTLS `ACCESS_DESCRIPTION` typed object API.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public typed `ACCESS_DESCRIPTION` object family; only selected extension-level helpers are available.
