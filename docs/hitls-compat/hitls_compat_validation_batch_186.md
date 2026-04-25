# openHiTLS Compatibility Validation Batch 186

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OPENSSL_LH_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes generic `OPENSSL_LHASH` helpers in `crypto/lhash`.
- openHiTLS exposes a public generic hash-table surface in [bsl_hash.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/hash/include/bsl_hash.h#L196), [bsl_hash.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/hash/include/bsl_hash.h#L219), [bsl_hash.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/hash/include/bsl_hash.h#L257), [bsl_hash.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/hash/include/bsl_hash.h#L322), and [bsl_hash.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/hash/include/bsl_hash.h#L345).

Verdict:
- `partial = 10`
- `not_available = 11`

Reasoning boundary:
- Core hash-table operations have a practical public analogue, but the helper surface still differs materially from `OPENSSL_LHASH`.
- Stats, error/load tuning, and thunk-specific helpers remain `not_available`.
