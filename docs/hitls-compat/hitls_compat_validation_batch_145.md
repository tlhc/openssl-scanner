# openHiTLS Compatibility Validation Batch 145

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `PKCS7_new`
- `PKCS7_new_ex`
- `PKCS7_free`
- `PKCS7_get_signer_info`
- `X509_add_ext`
- `X509_subject_name_hash`
- `ENGINE_by_id`
- `ENGINE_init`
- `ENGINE_free`
- `ENGINE_ctrl_cmd_string`
- `OBJ_nid2ln`
- `SSL_alert_desc_string_long`
- `SSL_alert_type_string_long`
- `X509_load_http`
- `BIO_do_connect_retry`

Status:
- completed

Initial evidence:
- OpenSSL exposes the PKCS7, X509, ENGINE, alert-string, HTTP load, and BIO connect-retry surfaces in [pkcs7.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h#L255), [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L775), [engine.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/engine.h#L421), [ssl.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ssl.h.in#L2008), [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L358), and [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L812).
- openHiTLS exposes a public CMS handle surface in [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L49) and [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L56), object-identifier/CID public APIs in [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L718), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L737), and [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L745), extension command surfaces in [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108) and [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L86), and only a state-string helper in [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L749).

Verdict:
- adjust to `partial`:
  - `PKCS7_new`
  - `PKCS7_new_ex`
  - `PKCS7_free`
  - `X509_add_ext`
- keep `not_available`:
  - `PKCS7_get_signer_info`
  - `X509_subject_name_hash`
  - `ENGINE_by_id`
  - `ENGINE_init`
  - `ENGINE_free`
  - `ENGINE_ctrl_cmd_string`
  - `OBJ_nid2ln`
  - `SSL_alert_desc_string_long`
  - `SSL_alert_type_string_long`
  - `X509_load_http`
  - `BIO_do_connect_retry`

Reasoning boundary:
- `PKCS7_new/new_ex/free` only reached `partial` because openHiTLS exposes a public CMS lifecycle surface, but not the OpenSSL `PKCS7 *` object model.
- `X509_add_ext` reached `partial` because openHiTLS exposes public extension-setting commands, including generic OID-based insertion for custom extensions, but not OpenSSL's `X509_EXTENSION *` insertion model.
- The rest stayed `not_available` because no public practical replacement path exists, even where some internal machinery or adjacent subsystem exists.
