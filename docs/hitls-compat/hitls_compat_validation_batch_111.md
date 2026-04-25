# openHiTLS Compatibility Validation Batch 111

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `GENERAL_NAME_cmp`
- `GENERAL_NAME_dup`
- `GENERAL_NAME_free`
- `GENERAL_NAME_get0_otherName`
- `GENERAL_NAME_get0_value`
- `GENERAL_NAME_it`
- `GENERAL_NAME_new`
- `GENERAL_NAME_print`
- `GENERAL_NAME_set0_othername`
- `GENERAL_NAME_set0_value`
- `GENERAL_NAME_set1_X509_NAME`

Status:
- completed

Initial evidence:
- OpenSSL exposes `GENERAL_NAME` as a public ASN.1 CHOICE type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L141), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L526), and the object helpers in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L527), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L528), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L546), and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L559).
- OpenSSL implements the CHOICE type and helpers in [v3_genn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_genn.c#L32), [v3_genn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_genn.c#L46), [v3_genn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_genn.c#L54), [v3_genn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_genn.c#L93), [v3_genn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_genn.c#L148), and [v3_genn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_genn.c#L217).
- openHiTLS exposes only a simpler public `HITLS_X509_GeneralName` struct and one free helper in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L135), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L156), and [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L96).
- openHiTLS parses supported GeneralName variants internally and frees them with internal/public helpers in [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L246), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L298), and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L369).

Verdict:
- keep `partial` for `GENERAL_NAME_free`.
- keep `not_available` for the remaining entries in scope.

Why:
- openHiTLS exposes a public free routine for parsed `HITLS_X509_GeneralName` values, so `GENERAL_NAME_free` has a narrow cleanup analogue.
- openHiTLS does not expose the OpenSSL `GENERAL_NAME` heap-object constructor, ASN.1 item object, duplication, comparator, getters, setters, or print helpers.
