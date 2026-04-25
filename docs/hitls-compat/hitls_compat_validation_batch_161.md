# openHiTLS Compatibility Validation Batch 161

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `X509_STORE_*` and `X509_STORE_CTX_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a large split object model for certificate verification in [x509_vfy.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_vfy.h.in#L425), [x509_vfy.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_vfy.h.in#L496), [x509_vfy.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_vfy.h.in#L509), and [x509_vfy.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_vfy.h.in#L669).
- openHiTLS public PKI headers expose a merged verification context model centered on [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L49), [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L58), [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L69), [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L78), [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L118), [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L129), and [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L154).
- The public ctrl command surface in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L327) covers direct verification knobs such as depth, flags, time, purpose, callback, user-data, peer chain, error, current cert, and chain retrieval.
- openHiTLS also exposes TLS-layer verify-store helpers in [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L49), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L59), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L71), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L80), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1076), [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1102), and [hitls_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert.h#L1446).
- But openHiTLS does not expose the full OpenSSL `X509_STORE` / `X509_STORE_CTX` callback, lookup, policy-tree, parent-context, DANE, param-object, or object-enumeration surface.

Verdict:
- adjust to `available`:
  - `X509_STORE_CTX_new`
  - `X509_STORE_CTX_free`
  - `X509_STORE_CTX_verify`
  - `X509_STORE_CTX_set_verify_cb`
  - `X509_STORE_CTX_get_verify_cb`
  - `X509_STORE_CTX_set_flags`
  - `X509_STORE_CTX_set_depth`
  - `X509_STORE_CTX_set_time`
  - `X509_STORE_CTX_set_error`
  - `X509_STORE_CTX_get_error_depth`
  - `X509_STORE_CTX_set_error_depth`
  - `X509_STORE_CTX_get_current_cert`
  - `X509_STORE_CTX_get0_chain`
  - `X509_STORE_CTX_set_ex_data`
  - `X509_STORE_CTX_set_purpose`
- keep or adjust to `partial`:
  - `23` interfaces
  - representative entries:
    - `X509_STORE_CTX_cleanup`
    - `X509_STORE_CTX_init`
    - `X509_STORE_CTX_init_rpk`
    - `X509_STORE_CTX_new_ex`
    - `X509_STORE_CTX_get0_untrusted`
    - `X509_STORE_CTX_get1_chain`
    - `X509_STORE_CTX_set0_crls`
    - `X509_STORE_CTX_set0_untrusted`
    - `X509_STORE_new`
    - `X509_STORE_free`
    - `X509_STORE_add_crl`
    - `X509_STORE_load_file`
    - `X509_STORE_load_file_ex`
    - `X509_STORE_load_locations`
    - `X509_STORE_load_locations_ex`
    - `X509_STORE_load_path`
    - `X509_STORE_set1_param`
    - `X509_STORE_set_default_paths`
    - `X509_STORE_set_default_paths_ex`
    - `X509_STORE_set_depth`
    - `X509_STORE_set_flags`
    - `X509_STORE_set_purpose`
    - `X509_STORE_up_ref`
- adjust to `not_available`:
  - the remaining `74` interfaces in this batch

Reasoning boundary:
- `available` was used only where openHiTLS exposes a direct public `StoreCtx` constructor, destructor, verification entry, or ctrl command for the same operational surface.
- `partial` was used where openHiTLS has a practical replacement path, but only through:
  - the merged `HITLS_X509_StoreCtx` model instead of separate `X509_STORE` and `X509_STORE_CTX`
  - TLS-layer verify-store wrappers
  - composition of multiple public calls instead of one OpenSSL helper
  - weaker ownership or parameter-object semantics
- `not_available` remains correct for OpenSSL-specific lookup callback families, DANE hooks, param-object getters/setters, policy-tree access, parent/store object introspection, object enumeration, and other surfaces with no public openHiTLS equivalent.
