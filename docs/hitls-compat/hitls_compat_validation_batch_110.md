# openHiTLS Compatibility Validation Batch 110

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `GENERAL_NAMES_free`
- `GENERAL_NAMES_it`
- `GENERAL_NAMES_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `GENERAL_NAMES` as a public stack-based ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L186) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L548), with ASN.1/template support in [v3_genn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_genn.c#L48) and [v3_genn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_genn.c#L52).
- openHiTLS exposes `HITLS_X509_GeneralName` as a plain public struct and SAN/AKI holders as `BslList` containers in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L156), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L167), and [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L198).
- openHiTLS parses and frees GeneralNames only through internal helpers in [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L369), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L310), and does not publish a `GENERAL_NAMES`-style constructor/item object in public headers.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public `GENERAL_NAMES` heap-object family or ASN.1 item/constructor APIs matching OpenSSL lifecycle semantics.
