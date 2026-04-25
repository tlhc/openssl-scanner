# openHiTLS Compatibility Validation Batch 122

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SXNETID_free`
- `SXNETID_it`
- `SXNETID_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `SXNETID` in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L237) and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L508), with ASN.1 implementation in [v3_sxnet.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_sxnet.c#L43) and [v3_sxnet.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_sxnet.c#L48).
- No public `SXNETID` typed API was found in openHiTLS headers or PKI modules.

Verdict:
- keep `not_available` for all entries in scope.
