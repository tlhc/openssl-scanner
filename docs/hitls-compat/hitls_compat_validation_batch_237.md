# openHiTLS Compatibility Validation Batch 237

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)
- OpenSSL docs:
  - https://docs.openssl.org/3.5/man3/PKCS7_sign/
  - https://docs.openssl.org/3.6/man3/PKCS7_verify/
  - https://docs.openssl.org/3.5/man3/PKCS7_sign_add_signer/

Scope:
- remaining `PKCS7_*` family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a broad standalone `PKCS7` family in public headers and `crypto/pkcs7`, including:
  - object constructors / destructors / ASN.1 items
  - SignedData signing and verification helpers
  - signer / cert / CRL adders
  - recipient / enveloped-data helpers
  - attribute setters / getters
  - print / stream / SMIME helpers
- openHiTLS public installed tree exposes a narrower `CMS` surface through:
  - `HITLS_CMS_ProviderNew`
  - `HITLS_CMS_Free`
  - `HITLS_CMS_ProviderParseBuff`
  - `HITLS_CMS_ProviderParseFile`
  - `HITLS_CMS_DataSign`
  - `HITLS_CMS_DataVerify`
  - `HITLS_CMS_DataInit`
  - `HITLS_CMS_DataUpdate`
  - `HITLS_CMS_DataFinal`
  - `HITLS_CMS_Ctrl`
- openHiTLS public CMS support is explicitly `SignedData`-centered:
  - parse currently supports `SignedData` only
  - public params cover digest, detached mode, cert lists, and CRL lists
  - public ctrl support only wires `HITLS_CMS_SET_MSG_MD`
- openHiTLS public installed tree does not expose a standalone `PKCS7_*` object family or wrapper-object helpers.

Verdict:
- keep `available = 0`
- adjust to `partial = 12`
- adjust to `not_available = 72`

Reasoning boundary:
- `partial` is limited to the high-level `SignedData` workflow that has a practical public replacement path through `HITLS_CMS`:
  - `PKCS7_sign`
  - `PKCS7_sign_ex`
  - `PKCS7_verify`
  - `PKCS7_sign_add_signer`
  - `PKCS7_add_signature`
  - `PKCS7_add_certificate`
  - `PKCS7_add_crl`
  - `PKCS7_dataInit`
  - `PKCS7_dataFinal`
  - `PKCS7_dataVerify`
  - `PKCS7_final`
  - `PKCS7_set_digest`
- These stay `partial` because:
  - openHiTLS uses `HITLS_CMS *`, not OpenSSL `PKCS7 *` or `PKCS7_SIGNER_INFO *`
  - public handling is constrained to `SignedData`
  - `BIO *`, object-lifecycle, and subobject-manipulation contracts are different
  - attribute-level and per-signer control are narrower
- `not_available` remains correct for the rest of the family because openHiTLS does not expose public standalone surfaces for:
  - `PKCS7_SIGNER_INFO_*` / `PKCS7_RECIP_INFO_*` / `PKCS7_SIGNED_*` / `PKCS7_ENVELOPE_*`
  - `PKCS7_DIGEST_*` / `PKCS7_ENCRYPT_*` / `PKCS7_SIGN_ENVELOPE_*`
  - generic `PKCS7_set_type` / `PKCS7_set_content` / `PKCS7_type_is_other`
  - recipient / encryption / decryption flows
  - attribute getters / setters and SMIME capability helpers
  - print / stream / timestamp-conversion helpers

Representative evidence:
- OpenSSL declarations:
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L239)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L254)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L271)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L281)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L284)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L289)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L293)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L296)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L322)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L327)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L331)
  - [pkcs7.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs7.h.in#L335)
- OpenSSL implementation evidence:
  - [pk7_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_lib.c#L20)
  - [pk7_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_lib.c#L72)
  - [pk7_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_lib.c#L89)
  - [pk7_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_lib.c#L396)
  - [pk7_smime.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_smime.c#L23)
  - [pk7_smime.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_smime.c#L72)
  - [pk7_smime.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs7/pk7_smime.c#L263)
- openHiTLS public declarations:
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L49)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L61)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L94)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L115)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L131)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L163)
  - [hitls_pki_cms.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cms.h#L184)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L469)
  - [hitls_pki_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_params.h#L37)
- openHiTLS SignedData-only boundary:
  - [hitls_cms_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_common.c#L207)
  - [hitls_cms_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_common.c#L215)
  - [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L1475)
  - [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L1493)
  - [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L1517)
  - [hitls_cms_util.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_util.c#L286)
  - [hitls_cms_util.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_util.c#L295)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L320)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L321)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L322)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L323)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L324)

Batch 237 inventory:
- total interfaces: `84`
- `partial = 12`
- `not_available = 72`
