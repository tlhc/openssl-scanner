# openHiTLS Compatibility Validation Batch 128

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `UTF8_getc`
- `UTF8_putc`
- `WHIRLPOOL`
- `WHIRLPOOL_BitUpdate`
- `WHIRLPOOL_Final`
- `WHIRLPOOL_Init`
- `WHIRLPOOL_Update`
- `X509V3_EXT_CRL_add_conf`
- `X509V3_EXT_CRL_add_nconf`
- `X509V3_EXT_REQ_add_conf`
- `X509V3_EXT_REQ_add_nconf`
- `X509V3_EXT_add`
- `X509V3_EXT_add_alias`
- `X509V3_EXT_add_conf`
- `X509V3_EXT_add_list`
- `X509V3_EXT_add_nconf`
- `X509V3_EXT_add_nconf_sk`
- `X509V3_EXT_cleanup`
- `X509V3_EXT_conf`
- `X509V3_EXT_conf_nid`
- `X509V3_EXT_d2i`
- `X509V3_EXT_get`
- `X509V3_EXT_get_nid`
- `X509V3_EXT_i2d`
- `X509V3_EXT_nconf`
- `X509V3_EXT_nconf_nid`
- `X509V3_EXT_print`
- `X509V3_EXT_print_fp`
- `X509V3_EXT_val_prn`

Status:
- completed

Initial evidence:
- OpenSSL exposes `UTF8_getc` and `UTF8_putc` as public ASN.1 utilities in [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L650) and implements them in [a_utf8.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_utf8.c#L28) and [a_utf8.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_utf8.c#L93).
- No public openHiTLS UTF-8 helper with equivalent `getc/putc` surface was found in headers or crypto/pki modules.
- OpenSSL exposes the legacy low-level `WHIRLPOOL` family in [whrlpool.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/whrlpool.h#L47) and [whrlpool.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/whrlpool.h#L53), with implementation in [wp_dgst.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/whrlpool/wp_dgst.c#L65), [wp_dgst.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/whrlpool/wp_dgst.c#L92), and [wp_dgst.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/whrlpool/wp_dgst.c#L253).
- openHiTLS public MD ids are limited to `MD5 / SHA1 / SHA2 / SHA3 / SHAKE / SM3` in [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L69) and the public digest-size map confirms the same set in [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L295). No `WHIRLPOOL` id or implementation was found.
- OpenSSL exposes the `X509V3_EXT_*` registry / config / print family in [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L621), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L678), [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L687), and [x509v3.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509v3.h.in#L701), with implementation spread across [v3_conf.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_conf.c#L58), [v3_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_lib.c#L25), and [v3_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/v3_prn.c#L24).
- openHiTLS public extension control is limited to `SKI / AKI / KUSAGE / SAN / BCONS / EXKUSAGE / CRLNUMBER / GENERIC` in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L86), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96), and [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L54).
- openHiTLS `GENERIC` is only a custom-extension OID path via `HITLS_X509_ExtCtrl(... GET|SET_GENERIC ...)` in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L232), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1206), and [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1323), not an OpenSSL-style `X509V3_EXT_*` registry / CONF / print surface.

Verdict:
- keep `not_available` for all entries in scope.
- `WHIRLPOOL` is corrected from `partial` to `not_available` because openHiTLS does not expose a public `WHIRLPOOL` algorithm id.
