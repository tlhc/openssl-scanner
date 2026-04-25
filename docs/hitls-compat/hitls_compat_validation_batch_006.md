# openHiTLS Compatibility Validation Batch 006

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `BIO_new`
- `BIO_s_mem`
- `BIO_read`
- `BIO_write`
- `BIO_pending`
- `BIO_new_file`
- `BIO_new_mem_buf`
- `BIO_get_mem_data`
- `BIO_reset`
- `BIO_printf`
- `BIO_free_all`

Status:
- completed

Initial evidence:
- OpenSSL declarations are concentrated in [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L602), [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L608), [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L618), [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L622), [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L632), [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L646), [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L648), and macros [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L515), [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L532), [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L536).
- openHiTLS public UIO surface is in [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L296), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L304), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L346), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L354), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L370), and [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L386).
- Implementations for creation/read/write/free are in [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L99), [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L152), [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L174), and [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L198).
- Memory/file method providers are in [uio_mem.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_mem.c#L393) and [uio_file.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_file.c#L322).

Current mapping baseline:
- already present as `partial`: `BIO_new`, `BIO_s_mem`, `BIO_read`, `BIO_write`, `BIO_new_file`, `BIO_new_mem_buf`, `BIO_free_all`
- currently missing: `BIO_pending`, `BIO_get_mem_data`, `BIO_reset`
- currently `not_available`: `BIO_printf`

Key question for this batch:
- which BIO helpers can be justified as public functional replacements through the UIO API, and which ones remain missing because OpenSSL exposes convenience macros or formatted I/O helpers that openHiTLS does not mirror directly.

## 1. `BIO_new`

Current JSON:
- `status = partial`
- `hitls = BSL_UIO_New(method)`

Verified evidence:
- OpenSSL declaration: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L608)
- openHiTLS declaration: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L346)
- implementation: [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L99)

Verdict:
- Keep `partial`

Why:
- Both sides create an I/O object from a method table.
- The public object and method types differ materially (`BIO/BIO_METHOD` vs `BSL_UIO/BSL_UIO_Method`), so this remains caller-adapted rather than one-call equivalent.

## 2. `BIO_s_mem`

Current JSON:
- `status = partial`
- `hitls = BSL_UIO_MemMethod()`

Verified evidence:
- OpenSSL declaration: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L646)
- openHiTLS declaration: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L296)
- implementation: [uio_mem.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_mem.c#L393)

Verdict:
- Keep `partial`

Why:
- The method-provider role matches.
- It still returns a different method object family and therefore stays `partial`.

## 3. `BIO_read`

Current JSON:
- `status = partial`
- `hitls = BSL_UIO_Read(uio, data, len, &readLen)`

Verified evidence:
- OpenSSL declaration: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L618)
- openHiTLS declaration: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L386)
- implementation: [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L198)

Verdict:
- Keep `partial`

Why:
- Both sides expose buffered read on the transport object.
- openHiTLS splits status and byte count, so the calling contract differs.

## 4. `BIO_write`

Current JSON:
- `status = partial`
- `hitls = BSL_UIO_Write(uio, data, len, &writeLen)`

Verified evidence:
- OpenSSL declaration: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L622)
- openHiTLS declaration: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L370)
- implementation: [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L174)

Verdict:
- Keep `partial`

Why:
- Same write role, different return-value model.

## 5. `BIO_pending`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L536)
- openHiTLS public ctrl code: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L109)
- memory/file ctrl implementations: [uio_mem.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_mem.c#L293), [uio_file.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_file.c#L273)
- ctrl dispatcher: [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L317)

Verdict:
- Add as `partial`

Why:
- Public ctrl support exists for pending-byte queries.
- The API shape is different: `BIO_pending()` returns an `int`, while openHiTLS uses `BSL_UIO_Ctrl(..., BSL_UIO_PENDING, sizeof(int64_t), &pending)`.

## 6. `BIO_new_file`

Current JSON:
- `status = partial`

Verdict:
- Keep `partial`

Why:
- Batch 001 already established that file UIO creation is public but not a one-call equivalent.

## 7. `BIO_new_mem_buf`

Current JSON:
- `status = partial`
- `hitls = BSL_UIO_New(BSL_UIO_MemMethod())`

Verified evidence:
- OpenSSL declaration: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L648)
- openHiTLS declarations: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L296), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L175)
- implementation: [uio_mem.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_mem.c#L35)

Verdict:
- Keep `partial`

Why:
- The public path exists as `BSL_UIO_New(BSL_UIO_MemMethod()) + BSL_UIO_Ctrl(..., BSL_UIO_MEM_NEW_BUF, len, buf)`.
- The object and initialization sequence differ from the OpenSSL one-call constructor.

## 8. `BIO_get_mem_data`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro and docs: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L515), [BIO_s_mem.3](openssl-3.0.9/doc/man/man3/BIO_s_mem.3:76)
- openHiTLS ctrl codes mention:
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L176)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L182)
- actual parameter types are private:
  - [uio_abstraction.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.h#L60)
  - [bsl_buffer.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/buffer/include/bsl_buffer.h#L32)

Verdict:
- Add as `not_available`

Why:
- openHiTLS has internal mechanisms to expose memory-buffer pointers.
- The usable parameter types for those ctrl paths are not part of the installed top-level public headers, so this is not a supported public compatibility path.

## 9. `BIO_reset`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro and docs: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L532), [BIO_ctrl.3](openssl-3.0.9/doc/man/man3/BIO_ctrl.3:110), [BIO_s_mem.3](openssl-3.0.9/doc/man/man3/BIO_s_mem.3:102)
- openHiTLS ctrl code: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L117)
- implementations: [uio_mem.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_mem.c#L280), [uio_file.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_file.c#L262)

Verdict:
- Add as `partial`

Why:
- Public reset support exists.
- The return-value model and exact per-method semantics remain method-specific, so wrapper adaptation is still needed.

## 10. `BIO_printf`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration/docs: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L815), [BIO_printf.3](openssl-3.0.9/doc/man/man3/BIO_printf.3:71)
- openHiTLS public string-write helper: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L453)

Verdict:
- Keep `not_available`

Why:
- openHiTLS has `BSL_UIO_Puts`, but it does not expose BIO-style formatting support.
- Needing external formatting first is beyond the public openHiTLS API equivalence boundary used by this truth library.

## 11. `BIO_free_all`

Current JSON:
- `status = partial`
- `hitls = BSL_UIO_FreeChain`

Verified evidence:
- OpenSSL declaration: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L632)
- OpenSSL implementation: [bio_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bio/bio_lib.c#L752)
- openHiTLS declaration: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L676)
- openHiTLS implementation: [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L648)

Verdict:
- Change to `available`

Why:
- Both are public void APIs that release a chain from the specified head.
- Both stop when they encounter a referenced node that should not be fully released.

## Batch 006 summary

Add:
- `BIO_pending`: `missing` -> `partial`
- `BIO_get_mem_data`: `missing` -> `not_available`
- `BIO_reset`: `missing` -> `partial`

Change:
- `BIO_free_all`: `partial` -> `available`

Keep:
- `BIO_new`
- `BIO_s_mem`
- `BIO_read`
- `BIO_write`
- `BIO_new_file`
- `BIO_new_mem_buf`
- `BIO_printf`

Main observation:
- The UIO abstraction is strong enough to cover the main BIO lifecycle and data-flow interfaces.
- The main remaining gap is memory-buffer pointer exposure, where openHiTLS leaks private parameter types into ctrl-code documentation instead of providing a clean installed public type.
