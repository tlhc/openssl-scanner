# openHiTLS Compatibility Validation Batch 001

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)

Scope:
- `SSL_CTX_new`
- `SSL_read`
- `SSL_write`
- `BIO_free`
- `BIO_new_file`
- `EVP_EncodeBlock`
- `EVP_DigestInit_ex`
- `EVP_DigestUpdate`
- `EVP_DigestFinal_ex`
- `SHA256_Init`
- `SHA256_Update`
- `SHA256_Final`

Rule used for status:
- `available`: openHiTLS public API provides a near-direct replacement with thin adaptation only.
- `partial`: openHiTLS public API can realize the function, but lifecycle, signature, return model, or setup differs materially.
- `not_available`: no direct public openHiTLS API exists for the OpenSSL symbol.
- Functional equivalence takes precedence over style equivalence.
- If openHiTLS public APIs can realize the same function but require caller-side adaptation because of different API style, return-value model, out-parameter model, or setup sequence, the interface is still counted as compatible at the function level.
- In that case, the verdict should normally be `partial`, not `not_available`.

Important boundary:
- This validation judges direct public API replacement, not "can be reimplemented somehow with multiple lower-level internal calls".
- Internal implementation evidence is used only to support the verdict, not to claim a public replacement API exists.

## Data Source Confirmation

Current scanner HiTLS output is sourced from one file only:
- Loader default path: [hitls_compat.py](oh/scanner/src/openssl_scanner/hitls_compat.py:34)
- Source export call-site lookup: [source_exporter.py](oh/scanner/src/openssl_scanner/source_exporter.py:143)
- Symbol summary lookup: [source_exporter.py](oh/scanner/src/openssl_scanner/source_exporter.py:215)
- JSON call-site lookup: [source_exporter.py](oh/scanner/src/openssl_scanner/source_exporter.py:245)
- Coverage summary: [source_exporter.py](oh/scanner/src/openssl_scanner/source_exporter.py:260)

Conclusion:
- All scanner HiTLS compatibility columns and coverage ratios currently derive from `hitls_compat.json`.

## Interface Validation

### 1. `SSL_CTX_new`

Current JSON:
- `status = partial`
- `hitls = HITLS_CFG_NewTLSConfig / HITLS_CFG_NewTLS12Config / HITLS_CFG_NewTLS13Config`

Verified openHiTLS evidence:
- Config creation: [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L437)
- TLS object creation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L43)
- Config constructor implementation: [config_tls.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/config/src/config_tls.c#L81)
- TLS object implementation: [conn_create.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_create.c#L61)

Assessment:
- The current entry direction is correct, but incomplete.
- `SSL_CTX_new()` in OpenSSL creates a reusable context directly from a method.
- openHiTLS splits this into two public steps:
  - create config via `HITLS_CFG_NewTLSConfig` or version-specific constructor
  - create connection object via `HITLS_New`

Verdict:
- Keep `partial`

Why partial:
- No single public openHiTLS API matches the OpenSSL one-step context creation model.
- openHiTLS uses a config-first, then context/object creation model.

Recommended JSON improvement:
- `hitls` should mention `HITLS_New` in addition to config constructors.

### 2. `SSL_read`

Current JSON:
- `status = partial`
- `hitls = HITLS_Read`

Verified openHiTLS evidence:
- Public declaration: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L200)
- Implementation entry: [conn_read.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_read.c#L493)

Assessment:
- Current mapping is accurate.

Why partial:
- `SSL_read` returns bytes read or error code semantics through return value.
- `HITLS_Read` returns `int32_t` status and uses `readLen` as an output parameter.
- This is not a thin rename; callers must adapt control flow.

Verdict:
- Keep `partial`

### 3. `SSL_write`

Current JSON:
- `status = partial`
- `hitls = HITLS_Write`

Verified openHiTLS evidence:
- Public declaration: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L234)
- Implementation entry: [conn_write.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_write.c#L207)

Assessment:
- Current mapping is accurate.

Why partial:
- `SSL_write` returns bytes written via return value.
- `HITLS_Write` returns status and writes the byte count to `writeLen`.
- Caller-side error handling and retry handling differ.

Verdict:
- Keep `partial`

### 4. `BIO_free`

Current JSON:
- `status = partial`
- `hitls = BSL_UIO_Free(uio)`

Verified openHiTLS evidence:
- Public declaration: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L354)
- Implementation entry: [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L152)

Assessment:
- Current mapping is accurate.

Why partial:
- `BIO_free` returns an `int`.
- `BSL_UIO_Free` returns `void`.
- Refcount/free semantics are conceptually similar, but caller contract differs.

Verdict:
- Keep `partial`

### 5. `BIO_new_file`

Current JSON:
- `status = partial`
- `hitls = BSL_UIO_New(BSL_UIO_FileMethod())`

Verified openHiTLS evidence:
- File method declaration: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L304)
- UIO creation declaration: [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L346)
- File method implementation: [uio_file.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_file.c#L322)
- Real usage example: [bsl_conf_def.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/conf/src/bsl_conf_def.c#L633)

Assessment:
- Current mapping direction is correct but underspecified.

Why partial:
- `BIO_new_file(path, mode)` both allocates and binds file behavior from a path and mode.
- openHiTLS exposes file-method construction and generic UIO creation, but not the same one-call public API shape in the mapping entry.
- The current `hitls` field does not explain the extra file setup steps.

Verdict:
- Keep `partial`

Recommended JSON improvement:
- Keep `BSL_UIO_New(BSL_UIO_FileMethod())`, but note that additional file-oriented setup is required beyond object creation.

### 6. `EVP_EncodeBlock`

Current JSON:
- `status = partial`
- `hitls = BSL_BASE64_Encode(ctx, in, inLen, out, outLen)`

Verified openHiTLS evidence:
- Public declaration: [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L54)
- Stateful encode API also exists: [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L104)
- Real usage example: [app_opt.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/apps/src/app_opt.c#L528)
- Implementation entry: [bsl_base64.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/base64/src/bsl_base64.c#L186)

Assessment:
- Current mapping is accurate.

Why partial:
- OpenSSL uses a simple 3-argument interface.
- openHiTLS uses output-length as an out parameter, and also exposes a stateful encode sequence.
- Callers need adaptation around buffer sizing and return model.

Verdict:
- Keep `partial`

### 7. `EVP_DigestInit_ex`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_MdInit`

Verified openHiTLS evidence:
- Public declaration: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L124)
- Context creation declaration: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48)
- Implementation entry: [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L174)
- Real usage example: [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L1742)

Assessment:
- Current mapping is accurate.

Why partial:
- OpenSSL chooses digest algorithm in `EVP_DigestInit_ex(ctx, type, engine)`.
- openHiTLS chooses digest algorithm at `CRYPT_EAL_MdNewCtx(id)` time, then `CRYPT_EAL_MdInit(ctx)` is one-argument initialization.
- Same functional phase, different lifecycle split.

Verdict:
- Keep `partial`

### 8. `EVP_DigestUpdate`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_MdUpdate`

Verified openHiTLS evidence:
- Public declaration: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L139)
- Implementation entry: [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L194)
- Real usage example: [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L979)

Assessment:
- Current mapping is slightly conservative.

Why partial:
- The update phase itself is close.
- But because the full EVP digest lifecycle in openHiTLS requires prior context construction and init under a different model, keeping `partial` is defensible at end-to-end API migration level.

Verdict:
- Keep `partial`

### 9. `EVP_DigestFinal_ex`

Current JSON:
- `status = partial`
- `hitls = CRYPT_EAL_MdFinal`

Verified openHiTLS evidence:
- Public declaration: [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L171)
- Implementation entry: [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L220)
- Real usage example: [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L980)

Assessment:
- Current mapping is slightly conservative but acceptable.

Why partial:
- The final phase is close in role.
- But openHiTLS still uses its own lifecycle and output-length handling model.

Verdict:
- Keep `partial`

### 10. `SHA256_Init`

Current JSON:
- `status = not_available`
- `hitls = null`

Verified openHiTLS evidence:
- Public digest API exists only through EAL:
  - context creation [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48)
  - init [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L124)
  - update [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L139)
  - final [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L171)

Assessment:
- Current entry is accurate under direct-public-API semantics.

Why not available:
- openHiTLS does not expose a low-level public `SHA256_Init` style API.
- Equivalent functionality exists only through the generic EAL digest context lifecycle.

Verdict:
- Keep `not_available`

### 11. `SHA256_Update`

Current JSON:
- `status = not_available`
- `hitls = null`

Assessment:
- Same reasoning as `SHA256_Init`.

Verdict:
- Keep `not_available`

### 12. `SHA256_Final`

Current JSON:
- `status = not_available`
- `hitls = null`

Assessment:
- Same reasoning as `SHA256_Init`.

Verdict:
- Keep `not_available`

## Summary

Entries judged directionally correct:
- `SSL_read`
- `SSL_write`
- `BIO_free`
- `EVP_EncodeBlock`
- `EVP_DigestInit_ex`
- `EVP_DigestUpdate`
- `EVP_DigestFinal_ex`
- `SHA256_Init`
- `SHA256_Update`
- `SHA256_Final`

Entries that should be improved for completeness:
- `SSL_CTX_new`
- `BIO_new_file`

Reason:
- Their current `hitls` field does not fully represent the public migration path.

Most important modeling issue in `hitls_compat.json`:
- The file mixes direct API replacement and migration-path guidance.
- This is workable for scanner output, but the status semantics should stay explicit:
  - direct public API replacement
  - versus functional migration with multiple openHiTLS calls
