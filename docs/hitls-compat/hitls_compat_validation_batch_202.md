# openHiTLS Compatibility Validation Batch 202

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- high-signal `d2i_*` parse/decode interfaces with a public openHiTLS parse or key-decode path

Status:
- completed

Initial evidence:
- OpenSSL exposes several `d2i_*` helpers that are functionally “decode DER or ASN.1 input into a public object”, including:
  - `d2i_CMS_ContentInfo`
  - `d2i_PKCS12`
  - `d2i_PUBKEY_ex`
  - `d2i_PrivateKey_ex`
  - `d2i_AutoPrivateKey_ex`
  - `d2i_X509_PUBKEY`
- openHiTLS public installed headers expose corresponding parser or key-codec surfaces:
  - `HITLS_CMS_ProviderParseBuff`
  - `HITLS_CMS_ProviderParseFile`
  - `HITLS_PKCS12_ParseBuff`
  - `HITLS_PKCS12_ParseFile`
  - `CRYPT_EAL_DecodeBuffKey`
  - `CRYPT_EAL_ProviderDecodeBuffKey`
  - `CRYPT_EAL_DecodeFileKey`
  - `CRYPT_EAL_ProviderDecodeFileKey`
- The practical boundary is clear:
  - openHiTLS can parse or decode the payload
  - but it returns `HITLS_CMS`, `HITLS_PKCS12`, or `CRYPT_EAL_PkeyCtx`
  - and it does not preserve OpenSSL's `d2i` cursor, BIO/FILE, wrapper-object, or `propq` contracts one-to-one

Verdict:
- keep `available = 0`
- adjust to `partial = 21`
- keep `not_available = 0`

Reasoning boundary:
- All entries in this batch are `partial`.
- The public openHiTLS parse/decode path is real and practical for migration:
  - CMS parse through `HITLS_CMS_ProviderParseBuff`
  - PKCS#12 parse through `HITLS_PKCS12_ParseBuff/ParseFile`
  - public/private key decode through `CRYPT_EAL_*Decode(Buff|File)Key`
- The remaining mismatch is structural rather than functional:
  - OpenSSL `d2i_*` cursor semantics (`**pp`)
  - BIO / FILE helper contracts
  - `propq` and wrapper-object semantics such as `CMS_ContentInfo` and `X509_PUBKEY`
