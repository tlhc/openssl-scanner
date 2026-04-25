# openHiTLS Compatibility Validation Batch 193

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `SSL_CTX_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a large `SSL_CTX` config and callback surface across `ssl.h.in`, `tls1.h`, `srtp.h`, and `ssl_lib.c`.
- openHiTLS exposes a public config-level analogue on `HITLS_Config`, with direct config setters spread across:
  - [hitls_debug.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_debug.h#L140)
  - [hitls_psk.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_psk.h#L110)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L271)
  - [hitls_security.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_security.h#L151)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L749)
  - [hitls_cookie.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cookie.h#L72)
  - [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1446)

Verdict:
- adjust to `available`:
  - `16`
- adjust to `partial`:
  - `13`
- keep `not_available`:
  - `37`

Representative `available`:
- `SSL_CTX_set_msg_callback -> HITLS_CFG_SetMsgCb`
- `SSL_CTX_set_post_handshake_auth -> HITLS_CFG_SetPostHandshakeAuthSupport`
- `SSL_CTX_set_psk_client_callback -> HITLS_CFG_SetPskClientCallback`
- `SSL_CTX_set_psk_find_session_callback -> HITLS_CFG_SetPskFindSessionCallback`
- `SSL_CTX_set_psk_server_callback -> HITLS_CFG_SetPskServerCallback`
- `SSL_CTX_set_psk_use_session_callback -> HITLS_CFG_SetPskUseSessionCallback`
- `SSL_CTX_set_quiet_shutdown -> HITLS_CFG_SetQuietShutdown`
- `SSL_CTX_set_record_padding_callback -> HITLS_CFG_SetRecordPaddingCb`
- `SSL_CTX_set_record_padding_callback_arg -> HITLS_CFG_SetRecordPaddingCbArg`
- `SSL_CTX_set_security_callback -> HITLS_CFG_SetSecurityCb`
- `SSL_CTX_set_security_level -> HITLS_CFG_SetSecurityLevel`
- `SSL_CTX_set_session_id_context -> HITLS_CFG_SetSessionIdCtx`
- `SSL_CTX_set_timeout -> HITLS_CFG_SetSessionTimeout`
- `SSL_CTX_set_tmp_dh_callback -> HITLS_CFG_SetTmpDhCb`
- `SSL_CTX_up_ref -> HITLS_CFG_UpRef`
- `SSL_CTX_use_psk_identity_hint -> HITLS_CFG_SetPskIdentityHint`

Representative `partial`:
- `SSL_CTX_set_default_verify_dir`
- `SSL_CTX_set_default_verify_paths`
- `SSL_CTX_set_ssl_version`
- `SSL_CTX_set_tlsext_max_fragment_length`
- `SSL_CTX_set_tlsext_ticket_key_evp_cb`
- `SSL_CTX_set_stateless_cookie_generate_cb`
- `SSL_CTX_set_stateless_cookie_verify_cb`
- `SSL_CTX_use_PrivateKey_ASN1`
- `SSL_CTX_use_certificate_ASN1`
- `SSL_CTX_use_cert_and_key`

Reasoning boundary:
- Direct config setters on `HITLS_Config` now count as `available` when they give a practical migration path from `SSL_CTX` configuration APIs.
- Items stayed `partial` where the capability exists, but only through:
  - composed multi-call paths
  - weaker/defaulted semantics
  - callback contract mismatch
  - object-model mismatch such as `SSL_METHOD` versus version bitmask configuration
- The remaining `37` stay `not_available` because openHiTLS still lacks public CT, DANE, SRP, NPN, keylog, serverinfo, RSA-legacy object, and several early-data or cert-type helper surfaces.
