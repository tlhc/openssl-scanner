# openHiTLS Compatibility Validation Batch 125

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `POLICYINFO_free`
- `POLICYINFO_it`
- `POLICYINFO_new`
- `POLICYQUALINFO_free`
- `POLICYQUALINFO_it`
- `POLICYQUALINFO_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `POLICYINFO` and `POLICYQUALINFO` as public X509v3 policy types in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L269), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L283), and declares the object helper family in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L577) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L578).
- OpenSSL implements the ASN.1 object family in [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L54), [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L59), [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L68), and [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L73).
- openHiTLS public PKI extension control only exposes `SKI / AKI / KUSAGE / SAN / BCONS / EXKUSAGE / CRLNUMBER / GENERIC` in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L86) and [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96).
- openHiTLS getter dispatch only handles `GET_SKI / GET_AKI / GET_CRLNUMBER / GET_KUSAGE / GET_BCONS / GET_SAN / GET_GENERIC` in [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1306).
- No public `POLICYINFO` or `POLICYQUALINFO` typed object/helper surface was found in openHiTLS headers or PKI sources.

Verdict:
- keep `not_available` for all entries in scope.
