# openHiTLS Compatibility Validation Batch 107

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `CERTIFICATEPOLICIES_free`
- `CERTIFICATEPOLICIES_it`
- `CERTIFICATEPOLICIES_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `CERTIFICATEPOLICIES` as a public X509v3 ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L292) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L576), with ASN.1/template support in [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L38), [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L48), and [v3_cpols.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_cpols.c#L52).
- openHiTLS public extension controls enumerate SKI, CRL number, AKI, key usage, basic constraints, SAN, and generic extension paths in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L105), and route only the supported commands through [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1378).

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public typed `CERTIFICATEPOLICIES` object family or OpenSSL-style ASN.1 allocator/item helpers.
