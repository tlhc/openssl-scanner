# openHiTLS Compatibility Validation Batch 124

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `NOTICEREF_free`
- `NOTICEREF_it`
- `NOTICEREF_new`
- `USERNOTICE_free`
- `USERNOTICE_it`
- `USERNOTICE_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `NOTICEREF` and `USERNOTICE` as public X509v3 policy helper types in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L259), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L264), and declares the object helper family in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L579) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L580).
- OpenSSL implements the ASN.1 object family in [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L75), [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L80), [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L82), and [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L87).
- openHiTLS public PKI extension control only exposes `SKI / AKI / KUSAGE / SAN / BCONS / EXKUSAGE / CRLNUMBER / GENERIC` in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L86) and [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96).
- openHiTLS getter dispatch only handles `GET_SKI / GET_AKI / GET_CRLNUMBER / GET_KUSAGE / GET_BCONS / GET_SAN / GET_GENERIC` in [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1306).
- No public `NOTICEREF` or `USERNOTICE` typed object/helper surface was found in openHiTLS headers or PKI sources.

Verdict:
- keep `not_available` for all entries in scope.
