# openHiTLS Compatibility Validation Batch 203

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `d2i_ASN1_*` typed ASN.1 decode family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a public `ASN1_*` object family and corresponding `d2i_ASN1_*` helpers through `asn1.h.in`, for example:
  - `DECLARE_ASN1_FUNCTIONS(ASN1_BIT_STRING)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_INTEGER)`
  - `DECLARE_ASN1_FUNCTIONS(ASN1_ENUMERATED)`
  - `d2i_ASN1_UINTEGER`
- openHiTLS public installed headers expose generic ASN.1 decode primitives through:
  - `BSL_ASN1_DecodeTemplate`
  - `BSL_ASN1_DecodePrimitiveItem`
- `BSL_ASN1_DecodePrimitiveItem` decodes into primitive storage like integers, bitstrings, and `BSL_TIME`, not into OpenSSL-style heap objects such as `ASN1_INTEGER *`, `ASN1_TIME *`, or `ASN1_STRING *`.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 22`

Reasoning boundary:
- This family is not blocked by missing parsing capability.
- The blocking boundary is the public object model.
- OpenSSL developers call `d2i_ASN1_*` to obtain concrete `ASN1_*` objects with stable ownership and downstream API compatibility.
- openHiTLS exposes only generic BSL ASN.1 decoding primitives and buffers, so there is no practical public replacement path for the `ASN1_*` object-family interfaces themselves.
