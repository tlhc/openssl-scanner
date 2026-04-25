# openHiTLS Compatibility Validation Batch 263

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl-3.0.9)

Scope:
- report-side unknown ASN.1 and PEM declaration/code-generation macros:
  - `ASN1_*` template macros and item-descriptor helpers
  - `DECLARE_ASN1_*`
  - `IMPLEMENT_ASN1_*`
  - `M_ASN1_*`
  - `static_ASN1_*`
  - PEM declaration/template helpers such as `DECLARE_PEM_rw` and `IMPLEMENT_PEM_rw`

Status:
- completed

Initial evidence:
- OpenSSL exposes ASN.1 declaration and code-generation macros in [asn1t.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1t.h.in#L158) and the generated wrapper family in [asn1t.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1t.h.in#L788).
- OpenSSL exposes ASN.1 BIO/FILE helper macros in [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L764) and [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L788).
- OpenSSL exposes PEM declaration templates in [pem.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/pem.h#L341).
- openHiTLS public installed surface exposes a generic ASN.1 template engine in [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L75):
  - list decode via [BSL_ASN1_DecodeListItem](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L148)
  - template decode via [BSL_ASN1_DecodeTemplate](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L163)
  - template encode via [BSL_ASN1_EncodeTemplate](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L177)
  - list encode via [BSL_ASN1_EncodeListItem](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L200)

Verdict:
- keep `available = 0`
- keep `partial = 0`
- set `not_available = 96`

Reasoning boundary:
- These OpenSSL interfaces are declaration-time or code-generation-time macros that create:
  - ASN.1 item descriptors
  - ASN.1 encode/decode wrappers
  - PEM read/write wrapper declarations
  - BIO/FILE adapter macros around OpenSSL object families
- openHiTLS public surface gives developers a generic ASN.1 template engine and list helpers. That surface is a lower-level adjacent building block, and it stops before an OpenSSL-compatible macro-generated item-descriptor and wrapper family.
- The reported macro names therefore stay `not_available` as OpenSSL interfaces even when openHiTLS has some underlying ASN.1 encode/decode capability.

Representative evidence:
- OpenSSL declarations and docs:
  - [asn1t.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1t.h.in#L158)
  - [asn1t.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1t.h.in#L788)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L764)
  - [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L788)
  - [pem.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/pem.h#L341)
- openHiTLS public declarations:
  - [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L75)
  - [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L148)
  - [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L163)
  - [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L177)
  - [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L200)

Batch 263 inventory:
- total interfaces: `96`
- `available = 0`
- `partial = 0`
- `not_available = 96`
