# openHiTLS Compatibility Validation Batch 129

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `X509V3_NAME_from_section`
- `X509V3_add1_i2d`
- `X509V3_add_standard_extensions`
- `X509V3_add_value`
- `X509V3_add_value_bool`
- `X509V3_add_value_bool_nf`
- `X509V3_add_value_int`
- `X509V3_add_value_uchar`
- `X509V3_conf_free`
- `X509V3_extensions_print`
- `X509V3_get_d2i`
- `X509V3_get_section`
- `X509V3_get_string`
- `X509V3_get_value_bool`
- `X509V3_get_value_int`
- `X509V3_parse_list`
- `X509V3_section_free`
- `X509V3_set_conf_lhash`
- `X509V3_set_ctx`
- `X509V3_set_issuer_pkey`
- `X509V3_set_nconf`
- `X509V3_string_free`

Status:
- completed

Initial evidence:
- OpenSSL exposes this helper/conf/value/context family in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L621), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L648), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L652), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L656), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L685), and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L780).
- OpenSSL implements the family across [v3_utl.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_utl.c#L79), [v3_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_lib.c#L122), [v3_conf.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_conf.c#L381), [v3_conf.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_conf.c#L436), [v3_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_prn.c#L139), and [v3_utl.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_utl.c#L1310).
- openHiTLS public extension control remains limited to typed `ExtCtrl` operations on `SKI / AKI / KUSAGE / SAN / BCONS / EXKUSAGE / CRLNUMBER / GENERIC` in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L86), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96), and [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L54).
- openHiTLS also exposes public extension-handle allocation/control in [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L66), [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L74), and [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L82).
- openHiTLS `GENERIC` only covers custom-extension OID get/set through `HITLS_X509_ExtCtrl` in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L232), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1206), and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1323).
- No public openHiTLS API was found for OpenSSL-style `CONF_VALUE` parsing, `X509V3_CTX` setup, value printers, or value coercion helpers.

Verdict:
- adjust to `partial`:
  - `X509V3_add1_i2d`
  - `X509V3_get_d2i`
- keep `not_available` for the remaining entries in scope.
