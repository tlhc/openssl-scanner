# openHiTLS Compatibility Validation Batch 188

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `DH_meth_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes legacy `DH_METHOD` object APIs in `dh_meth.c`.
- openHiTLS public installed headers expose DH algorithm operations, but no public method-object construction/customization surface.

Verdict:
- all `21` interfaces in this batch remain `not_available`

Reasoning boundary:
- Algorithm capability is not a practical public replacement path for `DH_METHOD` object APIs.
