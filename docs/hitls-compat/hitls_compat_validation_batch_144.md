# openHiTLS Compatibility Validation Batch 144

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `ERR_GET_REASON`
- `ERR_get_error_all`
- `ERR_get_error_line`
- `ERR_get_error_line_data`
- `ERR_print_errors_fp`
- `ERR_func_error_string`
- `ERR_raise`
- `ERR_PACK`

Status:
- completed

Initial evidence:
- OpenSSL exposes these helpers through the ERR public surface in [err.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/err.h.in#L418), [err.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/err.h.in#L425), and [crypto/conf/conf_mod.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/conf/conf_mod.c#L181).
- openHiTLS exposes its public error subsystem in [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L54), [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L103), [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L196), [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L247), [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L271), [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L284), [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L348), and [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L358).

Verdict:
- adjust to `available`:
  - `ERR_get_error_all`
  - `ERR_get_error_line`
- adjust to `partial`:
  - `ERR_GET_REASON`
  - `ERR_print_errors_fp`
- keep `not_available`:
  - `ERR_get_error_line_data`
  - `ERR_func_error_string`
  - `ERR_raise`
  - `ERR_PACK`

Reasoning boundary:
- `ERR_get_error_all` and `ERR_get_error_line` crossed into `available` because openHiTLS already exposes direct public retrieval APIs for the corresponding payload.
- `ERR_GET_REASON` stayed `partial` because the error-code layout is publicly documented, but there is no dedicated helper macro or function.
- `ERR_print_errors_fp` stayed `partial` because openHiTLS exposes public error-stack output, but not as a direct `FILE *` convenience helper.
