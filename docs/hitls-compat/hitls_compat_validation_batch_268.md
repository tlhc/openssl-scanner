# hitls_compat validation batch 268 - TLS SSL_* empty-note completion 2026-04-24

## Scope

75 SSL_* / SSL_CTX_* / SSL_SESSION_* symbols in `src/openssl_scanner/data/hitls_compat.json`
previously carried empty or `not analyzed` notes. This batch verifies each against
openHiTLS public TLS headers at `openhitls/include/tls/`
and assigns one of two rubrics:

- `facade`: a partial HITLS public API exists but contract/type/scope differs; bridge
  wrapper required.
- `absent`: no corresponding public HITLS surface; feature needs new public API or
  cannot be replaced without removing the OpenSSL call site.

Every claim below cites a specific HITLS header file and line, or an explicit
absence confirmed via `grep -r` over `include/tls/`.

## Distribution

- facade : 15
- absent : 60
- total  : 75

## Clusters

### early_data [absent]

**Assessment**: TLS 1.3 0-RTT/early-data is not implemented in openHiTLS. Source search of include/tls/ finds zero matches for early_data/0RTT. Ticket appdata channel also absent.

**Affected OpenSSL symbols**:
- `SSL_CTX_set_recv_max_early_data`
- `SSL_SESSION_get0_ticket_appdata`
- `SSL_SESSION_set1_ticket_appdata`
- `SSL_SESSION_set_max_early_data`
- `SSL_get_early_data_status`
- `SSL_get_max_early_data`
- `SSL_get_recv_max_early_data`
- `SSL_set_allow_early_data_cb`
- `SSL_set_max_early_data`
- `SSL_set_recv_max_early_data`

### srtp [absent]

**Assessment**: No DTLS-SRTP support in openHiTLS public API. Source search of include/tls/ finds zero matches for SRTP.

**Affected OpenSSL symbols**:
- `SSL_get_selected_srtp_profile`
- `SSL_get_srtp_profiles`
- `SSL_set_tlsext_use_srtp`

### serverinfo [absent]

**Assessment**: OpenSSL serverinfo TLS extension registration is not exposed in openHiTLS. Source search of include/tls/ finds zero matches for serverinfo.

**Affected OpenSSL symbols**:
- `SSL_CTX_use_serverinfo`
- `SSL_CTX_use_serverinfo_ex`
- `SSL_CTX_use_serverinfo_file`

### rpk [absent]

**Assessment**: RFC 7250 raw public keys are not in openHiTLS public API. Source search of include/tls/ finds zero matches for rpk/RawPublicKey.

**Affected OpenSSL symbols**:
- `SSL_SESSION_get0_peer_rpk`

### cert_type_negotiation [absent]

**Assessment**: RFC 7250 client/server certificate_type negotiation accessors not in openHiTLS.

**Affected OpenSSL symbols**:
- `SSL_get_negotiated_client_cert_type`
- `SSL_get_negotiated_server_cert_type`

### handshake_rtt [absent]

**Assessment**: Handshake RTT measurement is not in openHiTLS public API. Source search of include/tls/ finds zero matches for handshake RTT.

**Affected OpenSSL symbols**:
- `SSL_get_handshake_rtt`

### session_id_gen [absent]

**Assessment**: Custom session-id generator callback not in openHiTLS public API.

**Affected OpenSSL symbols**:
- `SSL_CTX_set_generate_session_id`
- `SSL_has_matching_session_id`
- `SSL_set_generate_session_id`

### session_secret_cb [absent]

**Assessment**: EAP-FAST-style session secret callback not in openHiTLS public API.

**Affected OpenSSL symbols**:
- `SSL_set_session_secret_cb`

### not_resumable_cb [absent]

**Assessment**: Not-resumable-session callback has no equivalent in openHiTLS public session API.

**Affected OpenSSL symbols**:
- `SSL_CTX_set_not_resumable_session_callback`
- `SSL_set_not_resumable_session_callback`

### rsa_key_loader [absent]

**Assessment**: RSA-specific key loaders not in openHiTLS; generic HITLS_SetPrivateKey / HITLS_LoadKeyFile (include/tls/hitls_cert.h) operate on algorithm-agnostic key objects.

**Affected OpenSSL symbols**:
- `SSL_CTX_use_RSAPrivateKey_ASN1`
- `SSL_CTX_use_RSAPrivateKey_file`
- `SSL_use_RSAPrivateKey`
- `SSL_use_RSAPrivateKey_ASN1`
- `SSL_use_RSAPrivateKey_file`

### ca_list_builders [facade]

**Assessment**: OpenSSL CA-list accessors take STACK_OF(X509_NAME). openHiTLS public API uses HITLS_CFG_AddCAIndication/HITLS_CFG_ClearCAList (hitls_config.h:905) and HITLS_TrustedCAList type; a compatibility facade can bridge the two models.

**Affected OpenSSL symbols**:
- `SSL_add1_to_CA_list`
- `SSL_add_client_CA`
- `SSL_dup_CA_list`
- `SSL_get0_CA_list`
- `SSL_set0_CA_list`

### store_cert_subjects [absent]

**Assessment**: openHiTLS does not expose helpers that walk a dir/file/URI store and return a stack of cert subjects; callers must enumerate certs and invoke HITLS_CFG_AddCAIndication individually.

**Affected OpenSSL symbols**:
- `SSL_add_dir_cert_subjects_to_stack`
- `SSL_add_file_cert_subjects_to_stack`
- `SSL_add_store_cert_subjects_to_stack`
- `SSL_load_client_CA_file_ex`

### rfd_wfd [absent]

**Assessment**: openHiTLS uses a BSL_UIO object model (HITLS_SetUio in hitls.h) rather than OpenSSL raw file-descriptor accessors; no direct rfd/wfd getter exists.

**Affected OpenSSL symbols**:
- `SSL_get_rfd`
- `SSL_get_wfd`

### buffer_alloc [absent]

**Assessment**: openHiTLS exposes HITLS_MODE_RELEASE_BUFFERS (hitls_type.h:157) as a mode bit, but no explicit alloc/free pair is provided in public API.

**Affected OpenSSL symbols**:
- `SSL_alloc_buffers`
- `SSL_free_buffers`

### ex_data [absent]

**Assessment**: openHiTLS does not implement OpenSSL CRYPTO_*_ex_data index mechanism; only a single security ex-data slot via HITLS_SetSecurityExData (hitls_security.h:255) is provided.

**Affected OpenSSL symbols**:
- `SSL_get_ex_data_X509_STORE_CTX_idx`

### verify_param [absent]

**Assessment**: openHiTLS has no X509_VERIFY_PARAM object; verification tuning goes through per-field setters on HITLS_CERT_Store and HITLS_Ctx rather than a param blob.

**Affected OpenSSL symbols**:
- `SSL_get0_param`
- `SSL_set1_param`

### extension_supported [absent]

**Assessment**: Custom extension registration query does not have a public openHiTLS equivalent; hitls_custom_extensions.h provides add-only APIs without a "was it registered" probe.

**Affected OpenSSL symbols**:
- `SSL_extension_supported`

### debug_print [absent]

**Assessment**: openHiTLS has no public session/trace/alert-string print helpers in include/tls/; HITLS_CFG_SetKeyLogCb (hitls_config.h:999) is for NSS keylog, not session dump.

**Affected OpenSSL symbols**:
- `SSL_SESSION_print`
- `SSL_SESSION_print_fp`
- `SSL_SESSION_print_keylog`
- `SSL_alert_type_string`
- `SSL_set_debug`
- `SSL_trace`

### cipher_list_query [facade]

**Assessment**: Public queries exist with different containers: HITLS_GetSupportedCiphers returns HITLS_CIPHER_List* (hitls.h:713); HITLS_GetClientCipherSuites returns uint16_t[] (hitls.h:694). Wire-level cipher bytes parse and pending-cipher query have no equivalent. Compatibility facade can adapt the list container and cipher-id lookup.

**Affected OpenSSL symbols**:
- `SSL_bytes_to_cipher_list`
- `SSL_get1_supported_ciphers`
- `SSL_get_client_ciphers`
- `SSL_get_pending_cipher`
- `SSL_get_shared_ciphers`

### sigalgs [facade]

**Assessment**: Closest public API is HITLS_GetSharedSigAlgs (hitls.h:515) which returns signatureScheme and keyType per index. SSL_get_sigalgs also exposes OID/digest NIDs, so a facade must synthesise OID metadata from HITLS_SignHashAlgo.

**Affected OpenSSL symbols**:
- `SSL_get_sigalgs`

### rstate [facade]

**Assessment**: Closest public API is HITLS_GetStateString(state) (hitls.h:749). OpenSSL returns a single-char state code ("RD"/"WR"/"SD") plus a long-form variant; a facade can map the HITLS_GetStateString result to the OpenSSL two-letter+long convention.

**Affected OpenSSL symbols**:
- `SSL_rstate_string`
- `SSL_rstate_string_long`

### session_time_ex [absent]

**Assessment**: HITLS_SESS_GetTimeout/HITLS_SESS_SetTimeout (hitls_session.h:666/656) expose a lifetime duration, not the absolute established-time returned by OpenSSL *_ex accessors.

**Affected OpenSSL symbols**:
- `SSL_SESSION_get_time_ex`
- `SSL_SESSION_set_time_ex`

### session_max_fragment_length [absent]

**Assessment**: HITLS_GetMaxSendFragment (hitls.h:1504) reads from HITLS_Ctx, not from HITLS_Session; no session-scoped getter is exposed.

**Affected OpenSSL symbols**:
- `SSL_SESSION_get_max_fragment_length`

### client_hello_ext_order [absent]

**Assessment**: HITLS_ClientHelloGetExtension (hitls.h:1703) fetches a single extension by type, not the full ordered extension type list emitted by the client.

**Affected OpenSSL symbols**:
- `SSL_client_hello_get_extension_order`

### check_chain [absent]

**Assessment**: No public probe that validates a cert chain against peer sigalg/cert-type hints is exposed by openHiTLS; application must test candidate keys via full handshake.

**Affected OpenSSL symbols**:
- `SSL_check_chain`

### copy_session_id [absent]

**Assessment**: Full SSL-to-SSL session-id copy helper not in openHiTLS; callers must extract/set via HITLS_SESS_* getters/setters.

**Affected OpenSSL symbols**:
- `SSL_copy_session_id`

### default_verify [absent]

**Assessment**: openHiTLS does not bake OpenSSL default-paths or OpenSSL trust_id presets into public API; caller supplies a HITLS_CERT_Store explicitly via HITLS_SetVerifyStore (hitls_cert.h:71).

**Affected OpenSSL symbols**:
- `SSL_CTX_set_default_verify_file`
- `SSL_CTX_set_trust`

### default_verify_store_uri [facade]

**Assessment**: HITLS_SetVerifyStore (hitls_cert.h:71) accepts a HITLS_CERT_Store object, not an OSSL_STORE URI. A facade must front-load the URI into a store object.

**Affected OpenSSL symbols**:
- `SSL_CTX_set_default_verify_store`

### use_cert_and_key [absent]

**Assessment**: One-call cert+privkey set with self-consistency check has no equivalent; closest helper HITLS_RemoveCertAndKey (hitls_cert.h) has opposite semantics.

**Affected OpenSSL symbols**:
- `SSL_use_cert_and_key`

### group_to_name [absent]

**Assessment**: openHiTLS exposes HITLS_NamedGroup enum values but no id-to-printable-name lookup.

**Affected OpenSSL symbols**:
- `SSL_group_to_name`

### export_keying_material_early [absent]

**Assessment**: HITLS_ExportKeyingMaterial (hitls.h:1579) is the post-handshake exporter; there is no early-traffic-secret exporter because early-data is not supported.

**Affected OpenSSL symbols**:
- `SSL_export_keying_material_early`

### certs_clear [facade]

**Assessment**: HITLS_ClearChainCerts (hitls_cert.h:732) clears only chain certs. OpenSSL SSL_certs_clear also drops leaf cert and private key; a facade must additionally invoke HITLS_RemoveCertAndKey to match behaviour.

**Affected OpenSSL symbols**:
- `SSL_certs_clear`
