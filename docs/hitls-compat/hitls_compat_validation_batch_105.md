# openHiTLS Compatibility Validation Batch 105

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `AUTHORITY_KEYID_free`
- `AUTHORITY_KEYID_it`
- `AUTHORITY_KEYID_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `AUTHORITY_KEYID` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L229) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L522), with ASN.1 implementation in [v3_akeya.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_akeya.c#L17) and [v3_akeya.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_akeya.c#L23).
- openHiTLS exposes a public extension getter for AKI through [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L99), [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L66), and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1310).

Verdict:
- keep `partial` for all entries in scope.

Why:
- openHiTLS does expose public AKI extension retrieval, but not an `AUTHORITY_KEYID *` heap object family with OpenSSL lifecycle semantics.
