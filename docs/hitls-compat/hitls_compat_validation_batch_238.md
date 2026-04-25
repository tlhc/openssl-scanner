# openHiTLS Compatibility Validation Batch 238

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)
- OpenSSL docs:
  - https://docs.openssl.org/3.5/man3/X509_NAME_add_entry_by_txt/
  - https://docs.openssl.org/3.5/man3/X509_NAME_print_ex/
  - https://docs.openssl.org/3.5/man3/X509_EXTENSION_set_object/
  - https://docs.openssl.org/3.5/man3/X509_PUBKEY_new/

Scope:
- remaining X509 subobject wrapper family lacking `analysis_doc`:
  - `X509_NAME_*`
  - `X509_NAME_ENTRY_*`
  - `X509_EXTENSION_*`
  - `X509_PUBKEY_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes four distinct public wrapper families here:
  - `X509_NAME_*`
  - `X509_NAME_ENTRY_*`
  - `X509_EXTENSION_*`
  - `X509_PUBKEY_*`
- openHiTLS public installed tree exposes:
  - DN-list helpers:
    - `HITLS_X509_DnListNew`
    - `HITLS_X509_DnListFree`
    - `HITLS_X509_AddDnName`
  - extension handle helpers:
    - `HITLS_X509_ExtNew`
    - `HITLS_X509_ExtFree`
    - `HITLS_X509_ExtCtrl`
    - `HITLS_X509_AttrCtrl`
  - certificate/public-key access paths on owning objects
- openHiTLS does not expose standalone public wrapper objects equivalent to:
  - `X509_NAME_ENTRY *`
  - `X509_PUBKEY *`
  - OpenSSL `ASN1_ITEM`-style `*_it`

Verdict:
- keep `available = 0`
- adjust to `partial = 17`
- adjust to `not_available = 35`

Reasoning boundary:
- `partial` is justified only where openHiTLS has a practical public replacement path:
  - DN-list operations:
    - `X509_NAME_add_entry`
    - `X509_NAME_add_entry_by_NID`
    - `X509_NAME_add_entry_by_OBJ`
    - `X509_NAME_free`
    - `X509_NAME_print`
    - `X509_NAME_print_ex`
    - `X509_NAME_print_ex_fp`
    - `X509_NAME_set`
  - extension-handle operations:
    - `X509_EXTENSION_create_by_NID`
    - `X509_EXTENSION_create_by_OBJ`
    - `X509_EXTENSION_dup`
    - `X509_EXTENSION_free`
    - `X509_EXTENSION_get_critical`
    - `X509_EXTENSION_new`
    - `X509_EXTENSION_set_critical`
    - `X509_EXTENSION_set_data`
    - `X509_EXTENSION_set_object`
- These stay `partial` because openHiTLS uses:
  - `BslList` + `HITLS_X509_DN` for DN content
  - `HITLS_X509_Ext *` plus `ExtCtrl/AttrCtrl` for extension content
  - owning-object getters / setters for embedded public keys
- `not_available` remains correct for:
  - all `X509_NAME_ENTRY_*` wrapper-object lifecycle / item helpers
  - all `X509_PUBKEY_*` standalone wrapper-object helpers
  - `X509_NAME_cmp`
  - `X509_NAME_delete_entry`
  - `X509_NAME_digest`
  - `X509_NAME_dup`
  - `X509_NAME_entry_count`
  - `X509_NAME_get0_der`
  - `X509_NAME_get_index_by_NID`
  - `X509_NAME_get_index_by_OBJ`
  - `X509_NAME_get_text_by_OBJ`
  - `X509_NAME_hash_ex`
  - `X509_NAME_hash_old`
  - `X509_NAME_it`
  - `X509_EXTENSION_get_object`
  - `X509_EXTENSION_it`
- The key correction in this batch is narrowing earlier coarse `partial` assumptions:
  - `DnListNew/AddDnName` helps build or print DN content, but it does not create a public `X509_NAME_ENTRY *` object model
  - `BSL_LIST_COUNT` cannot reproduce `X509_NAME_entry_count` semantics because openHiTLS inserts internal layer nodes into the DN list
  - `HITLS_X509_ExtCtrl` helps manipulate extension payloads, but it does not expose OpenSSL `ASN1_ITEM`, standalone `X509_EXTENSION_it`, or an object getter equivalent to `X509_EXTENSION_get_object`
  - owning-object public-key access does not create a standalone `X509_PUBKEY *` wrapper surface

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L814)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L820)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L832)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L845)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L857)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L861)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L862)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L870)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L885)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L892)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L947)
- OpenSSL implementation evidence:
  - [x_name.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_name.c#L489)
  - [x_name.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_name.c#L502)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L674)
  - [v3_conf.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_conf.c#L174)
  - [v3_conf.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_conf.c#L271)
  - [x_pubkey.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_pubkey.c#L268)
  - [x_pubkey.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_pubkey.c#L324)
  - [x_pubkey.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_pubkey.c#L445)
- openHiTLS public declarations:
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L66)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L74)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L82)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L100)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L110)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L119)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L131)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L145)
- openHiTLS implementation boundary:
  - [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L38)
  - [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L49)
  - [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L61)
  - [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L83)
  - [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L131)
  - [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L404)
  - [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L414)
  - [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L60)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1178)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1279)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1303)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1351)
  - [hitls_pki_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/print/src/hitls_pki_print.c#L1109)
  - [hitls_pki_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/print/src/hitls_pki_print.c#L1138)
  - [hitls_options.cmake](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/cmake/hitls_options.cmake#L439)

Batch 238 inventory:
- total interfaces: `52`
- `partial = 17`
- `not_available = 35`
