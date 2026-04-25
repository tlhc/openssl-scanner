# openHiTLS Compatibility Validation Batch 196

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `X509_VERIFY_PARAM_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes an explicit `X509_VERIFY_PARAM` object family in `x509_vfy.h.in`.
- openHiTLS public installed headers do not expose an equivalent standalone param object, but they do expose public verification-parameter control on `HITLS_X509_StoreCtx` via:
  - `HITLS_X509_StoreCtxNew`
  - `HITLS_X509_StoreCtxFree`
  - `HITLS_X509_StoreCtxCtrl`
  - `HITLS_X509_STORECTX_SET/GET_*` commands in `hitls_pki_types.h`

Verdict:
- adjust to `partial = 18`
- keep `not_available = 20`

Reasoning boundary:
- Depth, flags, time, purpose, host, peername, auth-level, and related verification controls have a practical public replacement path through `HITLS_X509_StoreCtxCtrl`, so those entries move to `partial`.
- Helpers that fundamentally depend on OpenSSL's standalone `X509_VERIFY_PARAM` object table, inheritance semantics, policy objects, name lookup table, or unsupported getters remain `not_available`.
