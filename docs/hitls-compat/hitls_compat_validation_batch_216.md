# openHiTLS Compatibility Validation Batch 216

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `CMS / PKCS7` top-level encode family still lacking `analysis_doc`:
  - `i2d_CMS_ContentInfo`
  - `i2d_CMS_bio`
  - `i2d_CMS_bio_stream`
  - `i2d_CMS_ReceiptRequest`
  - `i2d_PKCS7`
  - `i2d_PKCS7_bio`
  - `i2d_PKCS7_fp`
  - `i2d_PKCS7_bio_stream`
  - `i2d_PKCS7_DIGEST`
  - `i2d_PKCS7_ENCRYPT`
  - `i2d_PKCS7_ENC_CONTENT`
  - `i2d_PKCS7_ENVELOPE`
  - `i2d_PKCS7_ISSUER_AND_SERIAL`
  - `i2d_PKCS7_NDEF`
  - `i2d_PKCS7_RECIP_INFO`
  - `i2d_PKCS7_SIGNED`
  - `i2d_PKCS7_SIGNER_INFO`
  - `i2d_PKCS7_SIGN_ENVELOPE`

Status:
- completed

Initial evidence:
- OpenSSL exposes:
  - `DECLARE_ASN1_FUNCTIONS(CMS_ContentInfo)`
  - `i2d_CMS_bio`
  - `i2d_CMS_bio_stream`
  - `DECLARE_ASN1_FUNCTIONS(PKCS7)`
  - `i2d_PKCS7_bio`
  - `i2d_PKCS7_fp`
  - `i2d_PKCS7_bio_stream`
  - plus standalone `PKCS7_*` subobject encoder families
- openHiTLS public installed CMS surface exposes:
  - `HITLS_CMS_ProviderNew`
  - `HITLS_CMS_Free`
  - `HITLS_CMS_GenBuff`
  - `HITLS_CMS_GenFile`
  - `HITLS_CMS_DataInit`
  - `HITLS_CMS_DataUpdate`
  - `HITLS_CMS_DataFinal`
- openHiTLS CMS generation is constrained to `BSL_CID_PKCS7_SIGNEDDATA`.
- openHiTLS does not expose public wrapper-object encoders for:
  - `CMS_ReceiptRequest`
  - `PKCS7_SIGNED`
  - `PKCS7_ENVELOPE`
  - `PKCS7_SIGNER_INFO`
  - `PKCS7_RECIP_INFO`
  - `PKCS7_DIGEST`
  - `PKCS7_ENCRYPT`
  - `PKCS7_ENC_CONTENT`
  - `PKCS7_ISSUER_AND_SERIAL`
  - `PKCS7_SIGN_ENVELOPE`

Verdict:
- keep `available = 0`
- adjust to `partial = 7`
- adjust to `not_available = 11`

Reasoning boundary:
- `partial` is justified for the top-level message-handle encoders:
  - `i2d_CMS_ContentInfo`
  - `i2d_CMS_bio`
  - `i2d_CMS_bio_stream`
  - `i2d_PKCS7`
  - `i2d_PKCS7_bio`
  - `i2d_PKCS7_fp`
  - `i2d_PKCS7_bio_stream`
- The public replacement path is:
  - one-shot: `HITLS_CMS_GenBuff` or `HITLS_CMS_GenFile`
  - streaming SignedData flow: `HITLS_CMS_DataInit` / `HITLS_CMS_DataUpdate` / `HITLS_CMS_DataFinal` then `HITLS_CMS_GenBuff`
- These stay `partial` because:
  - openHiTLS uses `HITLS_CMS *`, not OpenSSL `CMS_ContentInfo *` or `PKCS7 *`
  - `_bio` / `_fp` / `_bio_stream` contracts are not preserved
  - public generation currently supports SignedData only
- `not_available` remains correct for:
  - `i2d_CMS_ReceiptRequest`
  - all `PKCS7_*` subobject encoders
  - `i2d_PKCS7_NDEF`
- The missing piece is the public standalone subobject encoder family and broader PKCS7 object model.

Representative evidence:
- OpenSSL declarations:
  - [cms.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cms.h.in#L60)
  - [cms.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cms.h.in#L61)
  - [cms.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cms.h.in#L123)
  - [cms.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/cms.h.in#L126)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L246)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L250)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L251)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L254)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L255)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L256)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L258)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L262)
- OpenSSL implementations:
  - [cms_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cms/cms_lib.c#L49)
  - [cms_io.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/cms/cms_io.c#L70)
  - [pk7_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_asn1.c#L83)
  - [pk7_mime.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_mime.c#L18)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L317)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L340)
- openHiTLS public declarations:
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L49)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L56)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L72)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L89)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L143)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L159)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L180)
- openHiTLS generation boundary:
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L61)
  - [hitls_cms_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_common.c#L248)
  - [hitls_cms_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_common.c#L261)
  - [hitls_cms_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_common.c#L298)
  - [hitls_cms_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_common.c#L321)
  - [hitls_cms_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_common.c#L336)
  - [hitls_cms_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_common.c#L351)

Batch 216 inventory:
- total interfaces: `18`
- `partial = 7`
- `not_available = 11`
