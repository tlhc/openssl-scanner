# openHiTLS Compatibility Validation Batch 031

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_set_bio`
- `SSL_set_fd`
- `BIO_set_flags`
- `BIO_s_file`

Status:
- completed

Initial evidence:
- This family is the next coherent high-frequency group without `analysis_doc`.
- Current scan aggregation shows:
  - `SSL_set_bio`: 12 repos
  - `SSL_set_fd`: 10 repos
  - `BIO_set_flags`: 10 repos
  - `BIO_s_file`: 8 repos
- All four map into the same openHiTLS transport abstraction boundary:
  - OpenSSL uses `BIO *`
  - openHiTLS uses `BSL_UIO *` plus explicit method construction and binding

## 1. `SSL_set_bio`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1575), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1290)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L78), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L287)
- Verdict: keep `partial`
- Why: `HITLS_SetUio` attaches transport I/O to the TLS ctx, but OpenSSL `SSL_set_bio` has more complicated rbio/wbio ownership and reference-adoption semantics that openHiTLS does not mirror.

## 2. `SSL_set_fd`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1569), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1377)
- openHiTLS declaration/implementation: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L320), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L346), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L598), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L78), [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L99), [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L352), [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L287)
- Verdict: keep `partial`
- Why: openHiTLS has no direct fd setter on the TLS object. The closest public path is composed:
  - `BSL_UIO_New(BSL_UIO_TcpMethod())`
  - `BSL_UIO_SetFD(uio, fd)`
  - `HITLS_SetUio(ctx, uio)`
  So the function-level capability exists, but not as a single OpenSSL-shaped API.

## 3. `BIO_set_flags`
- OpenSSL declaration/implementation: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L218), [bio_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bio/bio_lib.c#L216)
- openHiTLS declaration/implementation: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L609), [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L497)
- Verdict: keep `partial`
- Why: `BSL_UIO_SetFlags` serves the same broad purpose, but it is a status-returning function on a different object model (`BSL_UIO *` vs `BIO *`).

## 4. `BIO_s_file`
- OpenSSL declaration/implementation: [bio.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/bio.h.in#L601), [bss_file.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/bio/bss_file.c#L104)
- openHiTLS declaration/implementation: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L304), [uio_file.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_file.c#L322)
- Verdict: keep `partial`
- Why: `BSL_UIO_FileMethod()` is the method-object analogue, but using it still requires explicit `BSL_UIO_New(...)` construction, not a direct `BIO_METHOD *` factory used by `BIO_new(BIO_s_file())`.

## Batch 031 summary

Keep `partial`:
- `SSL_set_bio`
- `SSL_set_fd`
- `BIO_set_flags`
- `BIO_s_file`

Main observation:
- This batch is another clean example of “same transport role, different object model”.
- The missing piece is not capability, but composition:
  - OpenSSL packages transport binding around `BIO *`
  - openHiTLS packages it around `BSL_UIO *` plus explicit method/fd setup
