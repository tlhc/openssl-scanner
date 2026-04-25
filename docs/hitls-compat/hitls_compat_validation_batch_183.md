# openHiTLS Compatibility Validation Batch 183

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OPENSSL_sk_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes generic stack helpers in [stack.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/stack.h#L35).
- openHiTLS exposes a public generic list container in [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L197), [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L278), [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L290), and [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L302).

Verdict:
- `partial = 19`
- `not_available = 5`

Reasoning boundary:
- Core container operations have a practical public list analogue, but the container and ownership model differ from `OPENSSL_STACK`.
- `new_reserve`, `reserve`, `set`, `set_cmp_func`, and `is_sorted` still lack a practical public analogue.
