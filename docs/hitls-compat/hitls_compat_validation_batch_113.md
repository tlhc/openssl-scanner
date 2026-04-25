# openHiTLS Compatibility Validation Batch 113

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ISSUING_DIST_POINT_free`
- `ISSUING_DIST_POINT_it`
- `ISSUING_DIST_POINT_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `ISSUING_DIST_POINT` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L339) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L585).
- OpenSSL implements the ASN.1 sequence and allocator family in [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L332), [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L341), and wires the extension method at [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L348).
- openHiTLS public extension controls cover SKI, CRL number, AKI, key usage, basic constraints, SAN, and generic extension access in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L105), and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1378).
- Fresh repo search over `include/` and `pki/` for `ISSUING_DIST_POINT` returned no openHiTLS hit on 2026-04-16.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public `ISSUING_DIST_POINT` heap-object family or OpenSSL-style ASN.1 item/allocator API.
