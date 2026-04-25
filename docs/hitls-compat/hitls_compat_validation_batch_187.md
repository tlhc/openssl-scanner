# openHiTLS Compatibility Validation Batch 187

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `ENGINE_register_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes legacy ENGINE registration APIs in `engine.h`.
- openHiTLS public installed headers expose provider-based dispatch, not an ENGINE registry subsystem.

Verdict:
- all `20` interfaces in this batch remain `not_available`

Reasoning boundary:
- Provider registration is not a practical public analogue for legacy ENGINE registration APIs.
