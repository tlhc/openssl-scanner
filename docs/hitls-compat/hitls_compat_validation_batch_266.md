# openHiTLS Compatibility Validation Batch 266

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- report-side unknown PKI and serialization tails:
  - `X509_*`
  - `PKCS7_*`
  - `PKCS12_*`
  - `OCSP_*`
  - `X509V3_*`
  - `CONF_*` / `NCONF_*`
  - `BN_*`
  - remaining `d2i_*/i2d_*` BIO/FILE wrappers in this tail

Status:
- completed

Initial evidence:
- OpenSSL exposes time accessors, StoreCtx helpers, PKCS12/PKCS7 helpers, X509 name helpers, and BIO/FILE serialization wrappers across the relevant X509/PKCS/OCSP manpages and headers.
- openHiTLS public installed PKI surface exposes:
  - generic X509 object commands in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L54)
  - StoreCtx commands in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L338) and [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L118)
  - PKCS12 bag attributes in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L462) and [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L99)
  - X509 cert object control in [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108)
- current openHiTLS installed public headers still stop before:
  - a public BN family
  - a standalone PKCS7 object helper family
  - BIO/FILE wrapper helpers for the reported `d2i_*/i2d_*` symbols
  - X509 lookup/store callback helpers matching OpenSSL `X509_LOOKUP_*`

Verdict:
- keep `available = 0`
- set `partial = 9`
- set `not_available = 45`

Reasoning boundary:
- `partial` is justified where a practical public adjacent path exists:
  - `X509_get_notBefore`, `X509_get_notAfter`, `X509_set_notBefore`, `X509_set_notAfter`
    - `HITLS_X509_CertCtrl` with `HITLS_X509_GET_BEFORE_TIME`, `HITLS_X509_GET_AFTER_TIME`, `HITLS_X509_SET_BEFORE_TIME`, and `HITLS_X509_SET_AFTER_TIME`
  - `X509_STORE_CTX_get_app_data`, `X509_STORE_CTX_set_app_data`, and `X509_STORE_CTX_get_chain`
    - `HITLS_X509_StoreCtxCtrl` with `HITLS_X509_STORECTX_GET_USR_DATA`, `HITLS_X509_STORECTX_SET_USR_DATA`, and `HITLS_X509_STORECTX_GET_CERT_CHAIN`
  - `X509_extract_key`
    - `HITLS_X509_CertCtrl(HITLS_X509_GET_PUBKEY, ...)`
  - `PKCS12_add_friendlyname`
    - `HITLS_PKCS12_BagCtrl(HITLS_PKCS12_BAG_ADD_ATTR, ...)`
- these stay `partial` because the public contract differs in object model and value types:
  - openHiTLS returns/consumes its own time, certificate, key, and bag objects
  - OpenSSL uses wrapper object families such as `ASN1_TIME`, `X509_STORE_CTX`, and `PKCS12_SAFEBAG`
- `not_available` remains correct for:
  - all `BN_*` symbols in this batch
  - `PKCS7_*` detached/type-state helpers
  - `OCSP_REQ_CTX_*`, `OCSP_parse_url`, `OCSP_sendreq_nbio`
  - `d2i_*/i2d_*_bio/_fp` wrappers
  - `X509_LOOKUP_*`, `X509_STORE_get_by_subject`, `X509_STORE_set_lookup_crls_cb`
  - `X509_NAME_hash`, `X509_name_cmp`
  - `X509_get_ex_new_index`, `X509_STORE_CTX_get_ex_new_index`
  - `CONF_modules_free`, `NCONF_get_number`, and `X509V3_*` tails

Representative evidence:
- openHiTLS public declarations:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L54)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L68)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L77)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L338)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L351)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L366)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L462)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L118)
  - [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L99)

Batch 266 inventory:
- total interfaces: `54`
- `available = 0`
- `partial = 9`
- `not_available = 45`
