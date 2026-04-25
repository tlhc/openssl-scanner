# openHiTLS Compatibility Validation Batch 120

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `POLICY_MAPPINGS_it`
- `POLICY_MAPPING_free`
- `POLICY_MAPPING_it`
- `POLICY_MAPPING_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `POLICY_MAPPING` / `POLICY_MAPPINGS` in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L294), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L303), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L595), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L597), with implementation in [v3_pmaps.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_pmaps.c#L34), [v3_pmaps.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_pmaps.c#L39), and [v3_pmaps.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_pmaps.c#L44).
- No public policy-mapping typed API was found in openHiTLS PKI extension control or headers.

Verdict:
- keep `not_available` for all entries in scope.
