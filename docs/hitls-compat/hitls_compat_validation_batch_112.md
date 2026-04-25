# openHiTLS Compatibility Validation Batch 112

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `GENERAL_SUBTREE_free`
- `GENERAL_SUBTREE_it`
- `GENERAL_SUBTREE_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `GENERAL_SUBTREE` as a public Name Constraints ASN.1 type in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L305), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L599), and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L600).
- OpenSSL implements the ASN.1 sequence and allocators in [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L53), [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L67), and uses `GENERAL_SUBTREE_new()` in Name Constraints parsing at [v3_ncons.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_ncons.c#L150).
- openHiTLS public PKI headers and source tree expose no `GENERAL_SUBTREE` or Name Constraints public type family. Fresh repo search over `include/` and `pki/` for `GENERAL_SUBTREE`, `name constraints`, `permittedSubtrees`, and `excludedSubtrees` returned no hits on 2026-04-16.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose a public `GENERAL_SUBTREE` heap-object family or Name Constraints ASN.1 item/allocator surface.
