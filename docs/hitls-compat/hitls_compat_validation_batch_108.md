# openHiTLS Compatibility Validation Batch 108

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `CRL_DIST_POINTS_free`
- `CRL_DIST_POINTS_it`
- `CRL_DIST_POINTS_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `CRL_DIST_POINTS` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L227) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L582), with ASN.1/template implementation in [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L326) and [v3_crld.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_crld.c#L330).
- openHiTLS public CRL support handles issuer names, validity, AKI, and key-usage related extension flows in [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L369) and [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L99), but no public typed `CRL_DIST_POINTS` object family was found.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public typed `CRL_DIST_POINTS` object family.
