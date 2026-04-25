# openHiTLS Compatibility Validation Batch 231

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `PKCS12 standalone bag wrappers` lacking `analysis_doc`:
  - `i2d_PKCS12_BAGS`
  - `i2d_PKCS12_MAC_DATA`
  - `i2d_PKCS12_SAFEBAG`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone wrapper-object encoders for:
  - `PKCS12_MAC_DATA`
  - `PKCS12_SAFEBAG`
  - `PKCS12_BAGS`
- openHiTLS public installed PKCS12 surface exposes:
  - `HITLS_PKCS12_BagNew`
  - `HITLS_PKCS12_BagFree`
  - `HITLS_PKCS12_BagCtrl`
  - `HITLS_PKCS12_GenBuff`
  - `HITLS_PKCS12_GenFile`
- openHiTLS also has internal `HITLS_PKCS12_MacData` support.
- That public surface is centered on bag manipulation and whole-container generation, not standalone wrapper encoding.

Verdict:
- keep `available = 0`
- adjust to `partial = 0`
- adjust to `not_available = 3`

Reasoning boundary:
- The prior `partial` mapping was too coarse because it reused whole-container generation:
  - `HITLS_PKCS12_GenBuff`
  - `HITLS_PKCS12_ParseBuff`
- Whole-PKCS12 parse/gen does not provide a public standalone encoder for:
  - `PKCS12_BAGS`
  - `PKCS12_MAC_DATA`
  - `PKCS12_SAFEBAG`
- `HITLS_PKCS12_BagNew/BagCtrl` are bag-object manipulation APIs, not standalone DER wrapper encoders.
- `HITLS_PKCS12_MacData` is internal-only.
- Practical replaceability therefore fails at the public wrapper-object encode boundary.

Representative evidence:
- OpenSSL declarations:
  - [pkcs12.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs12.h.in#L295)
  - [pkcs12.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs12.h.in#L296)
  - [pkcs12.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pkcs12.h.in#L297)
- OpenSSL implementations:
  - [p12_asn.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs12/p12_asn.c#L47)
  - [p12_asn.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs12/p12_asn.c#L62)
  - [p12_asn.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs12/p12_asn.c#L81)
- openHiTLS public installed surface:
  - [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L38)
  - [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L77)
  - [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L86)
  - [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L99)
  - [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L209)
  - [hitls_pki_pkcs12.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_pkcs12.h#L225)
- openHiTLS internal-only evidence:
  - [hitls_pkcs12_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/pkcs12/include/hitls_pkcs12_local.h#L45)
  - [hitls_pkcs12_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/pkcs12/src/hitls_pkcs12_common.c#L728)
  - [hitls_pkcs12_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/pkcs12/src/hitls_pkcs12_common.c#L1089)

Batch 231 inventory:
- total interfaces: `3`
- `not_available = 3`
