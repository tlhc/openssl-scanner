# openHiTLS Compatibility Validation Batch 256

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `X509v3_*`, `ESS_*`, `NETSCAPE_*`, `NAMING_*`, `PROFESSION_*`, and `X509at_*` tails lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes several standalone PKI wrapper/helper families here:
  - generic extension-list helpers:
    - `X509v3_*`
  - generic attribute-stack helpers:
    - `X509at_*`
  - ESS / signing-certificate wrappers:
    - `ESS_*`
  - legacy Netscape wrappers:
    - `NETSCAPE_*`
  - standalone X509v3 wrapper objects:
    - `NAMING_AUTHORITY_*`
    - `PROFESSION_INFO_*`
- openHiTLS public installed surface exposes adjacent but narrower pieces:
  - `HITLS_X509_ExtCtrl`
  - `HITLS_X509_ExtNew`
  - `HITLS_X509_ExtFree`
  - `HITLS_X509_AttrCtrl`
- The actual public boundary is narrow:
  - `HITLS_X509_ExtCtrl` only supports a fixed subset of typed extension operations on `HITLS_X509_Ext`
  - `HITLS_X509_AttrCtrl` only supports CSR `requestedExtensions`
  - there is no public generic extension-list helper family
  - there is no public generic attribute-stack helper family
  - there is no public ESS, NETSCAPE, NAMING_AUTHORITY, or PROFESSION_INFO wrapper family

Verdict:
- keep `available = 0`
- keep `partial = 0`
- adjust to `not_available = 92`

Reasoning boundary:
- `X509v3_*` stays `not_available`
  - OpenSSL operates on generic `STACK_OF(X509_EXTENSION)` helper contracts
  - openHiTLS public `HITLS_X509_ExtCtrl` works on a typed `HITLS_X509_Ext` object with a fixed command set
  - there is no public extension-list traversal/add/delete/count helper family
- `X509at_*` stays `not_available`
  - OpenSSL operates on generic `STACK_OF(X509_ATTRIBUTE)` helpers
  - openHiTLS public `HITLS_X509_AttrCtrl` only covers CSR `requestedExtensions`
  - it does not expose generic attribute-stack add/get/delete/count helpers
- `ESS_*` stays `not_available`
  - OpenSSL exposes a public ESS ASN.1/object family plus signing-cert helpers
  - openHiTLS public installed tree has no ESS public API
- `NETSCAPE_*` stays `not_available`
  - OpenSSL exposes a legacy Netscape object family
  - openHiTLS public installed tree has no Netscape public API
- `NAMING_AUTHORITY_*` and `PROFESSION_INFO_*` stay `not_available`
  - OpenSSL exposes standalone X509v3 wrapper-object families
  - openHiTLS public installed tree has no public wrapper-object API for those types

Representative evidence:
- OpenSSL declarations and docs:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L960)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L986)
  - [X509_ATTRIBUTE.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/X509_ATTRIBUTE.pod#L24)
  - [X509_ATTRIBUTE.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/X509_ATTRIBUTE.pod#L191)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L953)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L1007)
  - [X509v3_get_ext_by_NID.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/X509v3_get_ext_by_NID.pod#L21)
  - [ess.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ess.h.in#L51)
  - [ess.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ess.h.in#L69)
  - [X509_dup.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/X509_dup.pod#L103)
  - [X509_dup.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/X509_dup.pod#L355)
- OpenSSL implementation evidence:
  - [x509_att.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_att.c#L21)
  - [x509_v3.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_v3.c#L22)
  - [ess_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ess/ess_asn1.c#L19)
  - [ess_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ess/ess_lib.c#L24)
  - [v3_admis.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_admis.c#L23)
- openHiTLS public declarations:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L96)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L116)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L66)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L74)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L145)
- openHiTLS implementation evidence:
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1178)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1303)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1368)
  - [hitls_x509_attrs.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_attrs.c#L294)
  - [hitls_x509_attrs.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_attrs.c#L329)

Batch 256 inventory:
- total interfaces: `92`
- `not_available = 92`
