# openHiTLS Compatibility Validation Batch 109

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `DIST_POINT_NAME_dup`
- `DIST_POINT_NAME_free`
- `DIST_POINT_NAME_it`
- `DIST_POINT_NAME_new`
- `DIST_POINT_free`
- `DIST_POINT_it`
- `DIST_POINT_new`
- `DIST_POINT_set_dpname`

Status:
- completed

Initial evidence:
- OpenSSL exposes `DIST_POINT_NAME` and `DIST_POINT` as public X509v3 ASN.1 types in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L192), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L216), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L583), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L584), and exposes the helper `DIST_POINT_set_dpname` in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L587).
- OpenSSL implements the ASN.1 types and helper in [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L310), [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L316), [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L318), [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L324), and [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L482).
- openHiTLS public extension controls enumerate SKI, CRL number, AKI, key usage, basic constraints, SAN, and generic extension paths in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L105), and route only the supported commands through [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1378).

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose public `DIST_POINT_NAME` or `DIST_POINT` heap-object APIs, and it does not expose an analogue of `DIST_POINT_set_dpname`.
