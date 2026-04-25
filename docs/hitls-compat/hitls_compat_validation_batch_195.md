# openHiTLS Compatibility Validation Batch 195

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `SSL_set_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a large `SSL_set_*` surface across `ssl.h.in`, `tls1.h`, and `ssl_lib.c`.
- openHiTLS public installed headers expose direct per-connection setters on `HITLS_Ctx`, including:
  - `HITLS_SetAlpnProtos`
  - `HITLS_SetCertCb`
  - `HITLS_SetCipherSuites`
  - `HITLS_SetDefaultPasswordCb`
  - `HITLS_SetDefaultPasswordCbUserdata`
  - `HITLS_SetInfoCb`
  - `HITLS_SetMsgCb`
  - `HITLS_SetPostHandshakeAuthSupport`
  - `HITLS_SetPsk*`
  - `HITLS_SetRecordPaddingCb`
  - `HITLS_SetRecordPaddingCbArg`
  - `HITLS_SetSessionIdCtx`
  - `HITLS_SetTmpDhCb`
  - `HITLS_SetVerifyResult`
  - `HITLS_SetUserData`

Verdict:
- adjust to `available = 17`
- adjust to `partial = 6`
- keep `not_available = 21`

Reasoning boundary:
- Direct public `HITLS_Set*` setters with a practical migration path were upgraded to `available`.
- `partial` was kept for surfaces where capability exists but the model differs, such as block padding callback semantics, hostflags/verify-purpose/trust abstractions, or read-buffer sizing.
- The remaining entries stay `not_available` because no public analogue exists for async, SRP, CT validation callback, stream-policy, SSL method swapping, direct fd setting, or similar surfaces.
