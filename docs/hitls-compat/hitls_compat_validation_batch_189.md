# openHiTLS Compatibility Validation Batch 189

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `ERR_load_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes per-library string-loader helpers across many subsystems.
- openHiTLS exposes generic public error-string batch registration via `BSL_ERR_AddErrStringBatch`, which is why this family is already mostly `partial`.

Verdict:
- keep the current split:
  - `partial = 30`
  - `not_available = 2`

Reasoning boundary:
- Generic error-string batch registration is a practical public replacement path for most `ERR_load_*_strings` helpers, but not an exact subsystem-specific analogue.
