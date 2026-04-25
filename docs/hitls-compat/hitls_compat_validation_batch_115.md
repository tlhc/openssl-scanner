# openHiTLS Compatibility Validation Batch 115

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASIdOrRange_free`
- `ASIdOrRange_it`
- `ASIdOrRange_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `ASIdOrRange` as a public RFC3779 ASN.1 type and declares the allocator/item family in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L797), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L809), and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L827).
- OpenSSL implements the ASN.1 CHOICE and generated allocator/item helpers in [v3_asid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_asid.c#L39), [v3_asid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_asid.c#L42), and [v3_asid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_asid.c#L55).
- openHiTLS public extension commands remain limited to SKI, AKI, key usage, SAN, basic constraints, extended key usage, CRL number, and generic extension access in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L90), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L105), and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1378).
- Fresh openHiTLS search over `include/` and `pki/` for `ASIdOrRange` returned no hits on 2026-04-16.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public `ASIdOrRange` heap-object family or RFC3779 ASN.1 item/allocator API.
