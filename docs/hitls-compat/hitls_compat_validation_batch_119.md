# openHiTLS Compatibility Validation Batch 119

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `POLICY_CONSTRAINTS_free`
- `POLICY_CONSTRAINTS_it`
- `POLICY_CONSTRAINTS_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `POLICY_CONSTRAINTS` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L320) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L605), with ASN.1 implementation in [v3_pcons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_pcons.c#L36) and [v3_pcons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_pcons.c#L41).
- No public policy-constraints typed API was found in openHiTLS PKI extension control or headers.

Verdict:
- keep `not_available` for all entries in scope.
