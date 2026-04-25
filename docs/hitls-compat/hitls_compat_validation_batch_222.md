# openHiTLS Compatibility Validation Batch 222

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `i2d_OSSL_*` family lacking `analysis_doc`:
  - `i2d_OSSL_ATTRIBUTES_SYNTAX`
  - `i2d_OSSL_BASIC_ATTR_CONSTRAINTS`
  - `i2d_OSSL_CMP_ATAVS`
  - `i2d_OSSL_CMP_MSG`
  - `i2d_OSSL_CMP_MSG_bio`
  - `i2d_OSSL_CMP_PKIHEADER`
  - `i2d_OSSL_CMP_PKISI`
  - `i2d_OSSL_CRMF_CERTID`
  - `i2d_OSSL_CRMF_CERTTEMPLATE`
  - `i2d_OSSL_CRMF_ENCRYPTEDVALUE`
  - `i2d_OSSL_CRMF_MSG`
  - `i2d_OSSL_CRMF_MSGS`
  - `i2d_OSSL_CRMF_PBMPARAMETER`
  - `i2d_OSSL_CRMF_PKIPUBLICATIONINFO`
  - `i2d_OSSL_CRMF_SINGLEPUBINFO`
  - `i2d_OSSL_IETF_ATTR_SYNTAX`
  - `i2d_OSSL_TARGET`
  - `i2d_OSSL_TARGETING_INFORMATION`
  - `i2d_OSSL_TARGETS`
  - `i2d_OSSL_USER_NOTICE_SYNTAX`

Status:
- completed

Initial evidence:
- OpenSSL exposes public `OSSL_*` ASN.1 object families for CMP / CRMF / target / notice syntax wrappers.
- openHiTLS public installed tree has no corresponding public object families or encode APIs for:
  - CMP message/header/status wrappers
  - CRMF template/message wrappers
  - target / targeting information wrappers
  - attribute syntax / user notice syntax wrappers
- openHiTLS tree only shows adjacent OID / purpose / internal-use traces, not a public encode surface.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 20`

Reasoning boundary:
- All 20 interfaces remain `not_available`.
- OpenSSL side here is a standalone wrapper-object ASN.1 encode family.
- openHiTLS public installed headers do not provide:
  - `OSSL_CMP_*` object creation or encode helpers
  - `OSSL_CRMF_*` object creation or encode helpers
  - `OSSL_TARGET*` object creation or encode helpers
  - `OSSL_*_SYNTAX` wrapper encode helpers
- Internal or adjacent traces do not create a public practical replacement path.

Representative evidence:
- OpenSSL declarations:
  - [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L222)
  - [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L225)
  - [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L250)
  - [cmp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cmp.h.in#L259)
  - [x509_acert.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_acert.h.in#L241)
  - [x509_acert.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_acert.h.in#L242)
- OpenSSL implementation / family evidence:
  - [cmp_msg.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cmp/cmp_msg.c#L1272)
  - [x_ietfatt.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_ietfatt.c#L94)
- openHiTLS adjacent-only evidence:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L311)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L182)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L201)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L246)

Batch 222 inventory:
- total interfaces: `20`
- `not_available = 20`
