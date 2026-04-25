# openHiTLS Compatibility Validation Batch 117

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASIdentifiers_free`
- `ASIdentifiers_it`
- `ASIdentifiers_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `ASIdentifiers` as a public RFC3779 ASN.1 sequence type and declares the allocator/item family in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L822), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L829), and related RFC3779 helpers in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L900).
- OpenSSL implements the ASN.1 sequence and generated allocator/item helpers in [v3_asid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_asid.c#L49), [v3_asid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_asid.c#L52), [v3_asid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_asid.c#L57), and uses the type in RFC3779 processing paths at [v3_asid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_asid.c#L154) and [v3_asid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_asid.c#L501).
- openHiTLS public extension commands remain limited to SKI, AKI, key usage, SAN, basic constraints, extended key usage, CRL number, and generic extension access in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L90), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L105), and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1378).
- Fresh openHiTLS search over `include/` and `pki/` for `ASIdentifiers` returned no hits on 2026-04-16.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public `ASIdentifiers` heap-object family or RFC3779 ASN.1 item/allocator API.
