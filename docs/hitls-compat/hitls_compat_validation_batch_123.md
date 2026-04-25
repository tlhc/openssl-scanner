# openHiTLS Compatibility Validation Batch 123

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SXNET_add_id_INTEGER`
- `SXNET_add_id_asc`
- `SXNET_add_id_ulong`
- `SXNET_free`
- `SXNET_get_id_INTEGER`
- `SXNET_get_id_asc`
- `SXNET_get_id_ulong`
- `SXNET_it`
- `SXNET_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes `SXNET` and helper APIs in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L247), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L512), and [v3_sxnet.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_sxnet.c#L52), [v3_sxnet.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_sxnet.c#L118), [v3_sxnet.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_sxnet.c#L151), [v3_sxnet.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_sxnet.c#L202), [v3_sxnet.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_sxnet.c#L232).
- No public `SXNET` typed API was found in openHiTLS headers or PKI modules.

Verdict:
- keep `not_available` for all entries in scope.
