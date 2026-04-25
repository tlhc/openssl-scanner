# openHiTLS Compatibility Validation Batch 114

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `NAME_CONSTRAINTS_check`
- `NAME_CONSTRAINTS_check_CN`
- `NAME_CONSTRAINTS_free`
- `NAME_CONSTRAINTS_it`
- `NAME_CONSTRAINTS_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `NAME_CONSTRAINTS` as a public X509v3 type and check helper family in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L315), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L589), and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L602).
- OpenSSL implements the ASN.1 sequence, allocator family, parser, and certificate/CN checks in [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L59), [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L68), [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L125), [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L134), [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L150), [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L250), and [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L409).
- openHiTLS public PKI headers and `include/` plus `pki/` source search returned no hits for `NAME_CONSTRAINTS`, `name constraints`, `permittedSubtrees`, or `excludedSubtrees` on 2026-04-16.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public `NAME_CONSTRAINTS` heap-object family or OpenSSL-style name-constraint evaluation helpers.
