# openHiTLS Compatibility Validation Batch 004

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ERR_get_error`
- `ERR_error_string`
- `ERR_clear_error`
- `ERR_reason_error_string`
- `ERR_GET_REASON`
- `ERR_GET_LIB`
- `ERR_peek_error`
- `ERR_peek_last_error`
- `ERR_error_string_n`
- `OPENSSL_free`
- `OBJ_obj2txt`

Status:
- completed

Rule reminder:
- `available`: near-direct public replacement with thin adaptation only.
- `partial`: public openHiTLS API can realize the function, but signature, object model, or lifecycle differs materially.
- `not_available`: no direct public openHiTLS API for the OpenSSL symbol.
- Functional equivalence takes precedence over style equivalence, but direct-public-API absence still prevents `available`.

## 1. `ERR_get_error`

Current JSON:
- `status = partial`
- `hitls = BSL_ERR_GetError()`

Verified evidence:
- OpenSSL declaration: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L406)
- openHiTLS declaration: [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L179)
- openHiTLS implementation: [err.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/err/src/err.c#L351)

Verdict:
- Change to `available`

Why:
- Same public role: pop the earliest pending error from the thread-local stack.
- The remaining mismatch is only error-code type/encoding, which is a thin adaptation.

## 2. `ERR_clear_error`

Current JSON:
- `status = available`
- `hitls = BSL_ERR_ClearError()`

Verified evidence:
- OpenSSL declaration: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L442)
- openHiTLS declaration: [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L222)
- implementation: [err.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/err/src/err.c#L179)

Verdict:
- Keep `available`

## 3. `ERR_peek_error`

Current JSON:
- `status = partial`
- `hitls = BSL_ERR_PeekErrorFileLine(NULL, NULL)`

Verified evidence:
- OpenSSL declaration: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L417)
- openHiTLS declaration: [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L133)
- implementation: [err.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/err/src/err.c#L356)

Verdict:
- Change to `available`

Why:
- There is a direct public peek API: `BSL_ERR_PeekError()`
- Current JSON replacement target is underspecified.

## 4. `ERR_peek_last_error`

Current JSON:
- `status = partial`
- `hitls = BSL_ERR_PeekLastErrorFileLine`

Verified evidence:
- OpenSSL declaration: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L429)
- openHiTLS declaration: [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L118)
- implementation: [err.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/err/src/err.c#L336)

Verdict:
- Change to `available`

Why:
- There is a direct public latest-error peek API: `BSL_ERR_PeekLastError()`
- Current JSON replacement target points to a richer file/line API but the thinner direct API exists.

## 5. `ERR_error_string`

Current JSON:
- `status = partial`
- `hitls = BSL_ERR_GetString(errCode)`

Verified evidence:
- OpenSSL declaration: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L444)
- openHiTLS declaration: [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L271)
- implementation: [err.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/err/src/err.c#L422)

Verdict:
- Keep `partial`

Why:
- Human-readable error text is obtainable.
- But OpenSSL provides formatter semantics and buffer-writing behavior that openHiTLS does not expose directly.

## 6. `ERR_error_string_n`

Current JSON:
- `status = partial`
- `hitls = BSL_ERR_GetString`

Verified evidence:
- OpenSSL declaration: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L445)
- openHiTLS declaration: [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L271)
- implementation: [err.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/err/src/err.c#L422)

Verdict:
- Keep `partial`

## 7. `ERR_reason_error_string`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L450)
- openHiTLS public error API offers only full-code string lookup: [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L271)
- no public reason-only extraction API found

Verdict:
- Keep `not_available`

Why:
- openHiTLS does not expose reason-only decomposition through a public API.

## 8. `ERR_GET_REASON`

Current JSON:
- missing

Verified evidence:
- OpenSSL inline extractor: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L257)
- no openHiTLS public equivalent found

Verdict:
- Add as `not_available`

Why:
- `BSL_ERR_GET_LIB` exists, but no `GET_REASON` counterpart is publicly exposed.

## 9. `ERR_GET_LIB`

Current JSON:
- missing

Verified evidence:
- OpenSSL inline extractor: [err.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/err.h.in#L243)
- openHiTLS macro: [bsl_err.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_err.h#L54)

Verdict:
- Add as `partial`

Why:
- Same high-level function exists, but error-code encoding differs between ecosystems.

## 10. `OPENSSL_free`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro: [crypto.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/crypto.h.in#L106)
- openHiTLS declaration: [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L250)
- usage across tree: many `BSL_SAL_Free(...)` call sites

Verdict:
- Add as `available`

Why:
- Public memory free API exists with the same effective ownership role and thin adaptation only.

## 11. `OBJ_obj2txt`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration: [objects.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/objects.h#L72)
- openHiTLS public object helpers:
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L755)
- implementation evidence:
  - [bsl_obj.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/obj/src/bsl_obj.c#L404)
  - [bsl_obj.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/obj/src/bsl_obj.c#L646)

Verdict:
- Change to `partial`

Why:
- openHiTLS can produce textual/numeric OID representations through split public helpers.
- It is not a one-call equivalent to `OBJ_obj2txt`, but the functionality is publicly realizable with wrapper logic.

## Batch 004 summary

Change current status verdicts:
- `ERR_get_error`: `partial` -> `available`
- `ERR_peek_error`: `partial` -> `available`
- `ERR_peek_last_error`: `partial` -> `available`
- `ERR_GET_REASON`: `missing` -> `not_available`
- `ERR_GET_LIB`: `missing` -> `partial`
- `OPENSSL_free`: `missing` -> `available`
- `OBJ_obj2txt`: `not_available` -> `partial`

Keep current status verdicts:
- `ERR_clear_error`
- `ERR_error_string`
- `ERR_error_string_n`
- `ERR_reason_error_string`

Main observation:
- openHiTLS error-stack core is stronger than the previous JSON suggested.
- Formatting and reason-extraction remain weaker than OpenSSL and therefore stay `partial` or `not_available`.
