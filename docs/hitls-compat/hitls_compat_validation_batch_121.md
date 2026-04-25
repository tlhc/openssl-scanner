# openHiTLS Compatibility Validation Batch 121

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `PROXY_CERT_INFO_EXTENSION_free`
- `PROXY_CERT_INFO_EXTENSION_it`
- `PROXY_CERT_INFO_EXTENSION_new`
- `PROXY_POLICY_free`
- `PROXY_POLICY_it`
- `PROXY_POLICY_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `PROXY_POLICY` / `PROXY_CERT_INFO_EXTENSION` in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L326), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L331), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L336), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L337), with implementation in [v3_pcia.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_pcia.c#L50), [v3_pcia.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_pcia.c#L56), and [v3_pci.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_pci.c#L58).
- No public proxy-cert-info typed API was found in openHiTLS PKI extension control or headers.

Verdict:
- keep `not_available` for all entries in scope.
