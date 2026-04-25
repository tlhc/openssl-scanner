# openHiTLS Compatibility Validation Batch 106

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BASIC_CONSTRAINTS_free`
- `BASIC_CONSTRAINTS_it`
- `BASIC_CONSTRAINTS_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `BASIC_CONSTRAINTS` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L121) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L505), with ASN.1 implementation in [v3_bcons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_bcons.c#L38) and [v3_bcons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_bcons.c#L43).
- openHiTLS exposes a public extension getter for basic constraints through [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L102) and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1318).

Verdict:
- keep `partial` for all entries in scope.

Why:
- openHiTLS does expose public basic-constraints retrieval, but not a `BASIC_CONSTRAINTS *` heap object family with OpenSSL lifecycle semantics.
