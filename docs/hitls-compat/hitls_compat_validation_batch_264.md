# openHiTLS Compatibility Validation Batch 264

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- report-side unknown TLS runtime helper tails:
  - `SSL_*`
  - `SSL_CTX_*`
  - `SSL_SESSION_*`
  - `DTLS*`
  - `TLS1_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes session-cache helpers, SNI helpers, chain helpers, group/sigalg helpers, deprecated temporary-ECDH helpers, DTLS timeout helpers, and TLS version macros across:
  - [SSL_CTX_set_session_cache_mode.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_set_session_cache_mode.pod#L5)
  - [SSL_CTX_add_extra_chain_cert.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_add_extra_chain_cert.pod#L5)
  - [SSL_CTX_add1_chain_cert.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_add1_chain_cert.pod#L5)
  - [SSL_CTX_set1_sigalgs.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_set1_sigalgs.pod#L5)
  - [SSL_CTX_set_tmp_ecdh.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_set_tmp_ecdh.pod#L5)
  - [SSL_get_current_cipher.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_get_current_cipher.pod#L5)
  - [SSL_get_peer_tmp_key.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_get_peer_tmp_key.pod#L5)
  - [SSL_get_extms_support.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_get_extms_support.pod#L5)
  - [SSL_want.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_want.pod#L6)
  - [tls1.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/tls1.h#L51)
- openHiTLS public installed TLS surface exposes the adjacent public runtime/config APIs here:
  - chain and extra-chain helpers in [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L638), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L872), and [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1052)
  - session-cache and ticket helpers in [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L271), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L305), [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L329), and [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L351)
  - SNI helpers in [hitls_sni.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_sni.h#L113)
  - version, group, sigalg, cipher, secure-renegotiation, link-MTU, and DTLS timeout helpers in [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L325), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L542), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L554), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L704), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L794), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L839), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1127), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1280), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1714), and [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1726)
  - config-level DH/group/signature/mode/read-ahead helpers in [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L651), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L879), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L892), [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1219), and [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1609)

Verdict:
- keep `available = 0`
- set `partial = 62`
- set `not_available = 74`

Reasoning boundary:
- `partial` is justified where openHiTLS has a practical public runtime/config replacement path:
  - chain and extra-chain maintenance through `HITLS_CFG_AddChainCert`, `HITLS_CFG_GetChainCerts`, `HITLS_CFG_ClearChainCerts`, `HITLS_CFG_AddExtraChainCert`, `HITLS_CFG_GetExtraChainCerts`, `HITLS_CFG_ClearExtraChainCerts`, `HITLS_CFG_BuildCertChain`, `HITLS_BuildCertChain`, and `HITLS_ClearChainCerts`
  - session-cache mode and cache-size controls through `HITLS_CFG_SetSessionCacheMode`, `HITLS_CFG_GetSessionCacheMode`, `HITLS_CFG_SetSessionCacheSize`, and `HITLS_CFG_GetSessionCacheSize`
  - SNI callback/arg and ticket-key controls through `HITLS_CFG_SetServerNameCb`, `HITLS_CFG_SetServerNameArg`, `HITLS_CFG_SetTicketKeyCallback`, and `HITLS_CFG_SetSessionTicketKey`
  - group, signature, DH, mode, version, cipher, and DTLS timeout helpers through `HITLS_CFG_SetGroupList`, `HITLS_CFG_SetSignature`, `HITLS_CFG_SetTmpDh`, `HITLS_SetGroupList`, `HITLS_SetSigalgsList`, `HITLS_SetTmpDh`, `HITLS_SetModeSupport`, `HITLS_GetCurrentCipher`, `HITLS_GetNegotiatedVersion`, `HITLS_GetClientVersion`, `HITLS_GetNegotiateGroup`, `HITLS_GetSecureRenegotiationSupport`, `HITLS_SetLinkMtu`, `HITLS_DtlsGetTimeout`, and `HITLS_DtlsProcessTimeout`
- these remain `partial` because the public contract still differs in one or more of:
  - OpenSSL macro helpers versus explicit openHiTLS status-return functions
  - OpenSSL `STACK_OF(X509)` and store-object views versus openHiTLS chain/store objects
  - OpenSSL NID/string helper contracts versus openHiTLS enum/list contracts
  - deprecated OpenSSL `EC_KEY *` temporary-ECDH helpers versus openHiTLS group configuration
- `not_available` remains correct for:
  - `SSL_CTX` / `SSL` / `SSL_SESSION` ex-data allocators and app-data surfaces
  - OCSP stapling callback and status-object helpers
  - session-cache statistics counters
  - verify-store and chain-store getter/setter helpers
  - async/retry-verify/want-state helpers
  - NPN/debug/pipeline/split-fragment helpers
  - raw runtime getters such as `SSL_get_peer_tmp_key`, `SSL_get_server_tmp_key`, `SSL_get_tmp_key`, `SSL_get0_raw_cipherlist`, and `SSL_get1_groups`
  - `SSL_get_extms_support`
    - OpenSSL reports whether the current session used EMS
    - openHiTLS public EMS getters expose support-mode state

Representative evidence:
- OpenSSL declarations and docs:
  - [SSL_CTX_set_session_cache_mode.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_set_session_cache_mode.pod#L5)
  - [SSL_CTX_add_extra_chain_cert.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_add_extra_chain_cert.pod#L5)
  - [SSL_CTX_add1_chain_cert.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_add1_chain_cert.pod#L5)
  - [SSL_CTX_set1_sigalgs.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_set1_sigalgs.pod#L5)
  - [SSL_CTX_set_tmp_ecdh.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_CTX_set_tmp_ecdh.pod#L5)
  - [SSL_get_current_cipher.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_get_current_cipher.pod#L5)
  - [SSL_get_peer_tmp_key.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_get_peer_tmp_key.pod#L5)
  - [SSL_get_extms_support.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_get_extms_support.pod#L5)
  - [SSL_want.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/SSL_want.pod#L6)
  - [tls1.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/tls1.h#L51)
- openHiTLS public declarations:
  - [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L638)
  - [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L872)
  - [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1052)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L329)
  - [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L340)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L879)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L892)
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L704)
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L794)
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1127)
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1714)
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1726)

Batch 264 inventory:
- total interfaces: `136`
- `available = 0`
- `partial = 62`
- `not_available = 74`
