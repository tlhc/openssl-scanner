# openHiTLS Compatibility Validation Batch 221

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `i2d_ASN1_*` typed family lacking `analysis_doc`:
  - `i2d_ASN1_BIT_STRING`
  - `i2d_ASN1_BMPSTRING`
  - `i2d_ASN1_ENUMERATED`
  - `i2d_ASN1_GENERALIZEDTIME`
  - `i2d_ASN1_GENERALSTRING`
  - `i2d_ASN1_IA5STRING`
  - `i2d_ASN1_INTEGER`
  - `i2d_ASN1_NULL`
  - `i2d_ASN1_OBJECT`
  - `i2d_ASN1_OCTET_STRING`
  - `i2d_ASN1_PRINTABLE`
  - `i2d_ASN1_PRINTABLESTRING`
  - `i2d_ASN1_SEQUENCE_ANY`
  - `i2d_ASN1_SET_ANY`
  - `i2d_ASN1_T61STRING`
  - `i2d_ASN1_TIME`
  - `i2d_ASN1_TYPE`
  - `i2d_ASN1_UNIVERSALSTRING`
  - `i2d_ASN1_UTCTIME`
  - `i2d_ASN1_UTF8STRING`
  - `i2d_ASN1_VISIBLESTRING`
  - `i2d_ASN1_bio_stream`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone `ASN1_*` typed object encode entrypoints through public declarations such as:
  - `DECLARE_ASN1_FUNCTIONS(ASN1_BIT_STRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_INTEGER)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_ENUMERATED)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_VISIBLESTRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_UNIVERSALSTRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_UTF8STRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_NULL)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_BMPSTRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_PRINTABLESTRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_T61STRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_IA5STRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_GENERALSTRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_UTCTIME)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_GENERALIZEDTIME)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_TIME)`
  - plus `i2d_ASN1_bio_stream`
- openHiTLS public installed ASN.1 surface exposes generic building blocks:
  - `BSL_ASN1_EncodeTemplate`
  - `BSL_ASN1_EncodeListItem`
  - `BSL_ASN1_EncodeLimb`
  - `BSL_ASN1_DecodePrimitiveItem`
  - `BSL_ASN1_DecodeTemplate`
- openHiTLS public installed headers do not expose OpenSSL-style standalone `ASN1_*` wrapper object encoders.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 22`

Reasoning boundary:
- All 22 interfaces remain `not_available`.
- The openHiTLS public ASN.1 APIs are generic serialization primitives.
- They help internal encoders build DER/ASN.1 structures, but they do not expose:
  - OpenSSL `ASN1_*` wrapper object families
  - typed `i2d_ASN1_*` public helper surface
  - `BIO`-stream helper equivalents for arbitrary `ASN1_VALUE *`
- Practical replaceability therefore fails at the public object-model boundary.

Representative evidence:
- OpenSSL declarations:
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L547)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L570)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L576)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L596)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L609)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L610)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L611)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L612)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L613)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L628)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L629)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L630)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L631)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L632)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L633)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L634)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/asn1.h.in#L892)
- OpenSSL implementation evidence:
  - [asn_mime.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/asn_mime.c#L69)
  - [a_object.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/a_object.c#L21)
  - [asn1_gen.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/asn1_gen.c#L439)
  - [asn1_gen.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/asn1_gen.c#L441)
- openHiTLS public declarations:
  - [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174)
  - [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
  - [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L217)
- openHiTLS implementation evidence:
  - [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
  - [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L686)
  - [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1286)
  - [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1320)
  - [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1389)

Batch 221 inventory:
- total interfaces: `22`
- `not_available = 22`
