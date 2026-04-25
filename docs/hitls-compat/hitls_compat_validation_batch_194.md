# openHiTLS Compatibility Validation Batch 194

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `SSL_get_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a broad `SSL_get_*` readback surface across `ssl.h.in`, `tls1.h`, and `ssl_lib.c`.
- openHiTLS public installed headers expose a narrower set of direct context getters, including:
  - `HITLS_GetDefaultPasswordCb`
  - `HITLS_GetDefaultPasswordCbUserdata`
  - `HITLS_GetCAList`
  - `HITLS_GetCipherSuites`
  - `HITLS_GetKeyUpdateType`
  - `HITLS_GetRecordPaddingCbArg`
  - `HITLS_GetUserData`

Verdict:
- adjust to `available = 4`
- adjust to `partial = 6`
- keep `not_available = 41`

Representative `available`:
- `SSL_get_default_passwd_cb -> HITLS_GetDefaultPasswordCb`
- `SSL_get_default_passwd_cb_userdata -> HITLS_GetDefaultPasswordCbUserdata`
- `SSL_get_key_update_type -> HITLS_GetKeyUpdateType`
- `SSL_get_record_padding_callback_arg -> HITLS_GetRecordPaddingCbArg`

Representative `partial`:
- `SSL_get_client_CA_list -> HITLS_GetCAList`
- `SSL_get_ciphers -> HITLS_GetCipherSuites`
- `SSL_get_cipher_list -> HITLS_GetCipherSuites + HITLS_CFG_GetCipherSuiteName`
- `SSL_get_ex_data -> HITLS_GetUserData`
- `SSL_get_peer_signature_type_nid -> HITLS_GetPeerSignScheme`
- `SSL_get_signature_type_nid -> HITLS_GetLocalSignScheme`

Reasoning boundary:
- Direct public ctx getters with matching operational semantics were upgraded to `available`.
- Readbacks that exist but differ in returned object model, container type, or numeric namespace stayed `partial`.
- `SSL_get_version` was corrected back to `not_available` because openHiTLS only exposes supported-version bitmask query, not a public negotiated-version string getter analogous to OpenSSL.
