# openHiTLS Compatibility Validation Batch 079

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_BIT_STRING_free`
- `ASN1_BIT_STRING_new`
- `ASN1_BIT_STRING_set`
- `ASN1_BIT_STRING_get_bit`
- `ASN1_BIT_STRING_set_bit`
- `ASN1_BIT_STRING_check`
- `ASN1_BIT_STRING_num_asc`
- `ASN1_BIT_STRING_set_asc`

Status:
- completed

Initial evidence:
- openHiTLS public ASN.1 support exposes `BSL_ASN1_BitString` as a plain data structure plus template-based encode/decode APIs.
- That is a different surface from OpenSSL's object-style `ASN1_BIT_STRING_*` helper family.
- The closest public openHiTLS usage patterns are:
  - decode into `BSL_ASN1_BitString` via `BSL_ASN1_DecodePrimitiveItem`
  - encode caller-managed bit-string content via `BSL_ASN1_EncodeTemplate`
- No public helper family exists for bit access, named-bit tables, or object lifecycle.

## 1. `ASN1_BIT_STRING_free`
- OpenSSL declaration/implementation: [a_bitstr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_bitstr.c#L139)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L96), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174)
- Verdict: keep `not_available`
- Why: openHiTLS exposes `BSL_ASN1_BitString` as a plain struct, not an allocated `ASN1_BIT_STRING` object with lifecycle helpers.

## 2. `ASN1_BIT_STRING_new`
- OpenSSL declaration/implementation: [a_bitstr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_bitstr.c#L98)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L96), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_BIT_STRING` object constructor.

## 3. `ASN1_BIT_STRING_set`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L590), [a_bitstr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_bitstr.c#L16)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L96), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L775)
- Verdict: keep `not_available`
- Why: openHiTLS encodes bit strings through caller-managed `BSL_ASN1_BitString` plus templates, not through a mutable `ASN1_BIT_STRING` object setter.

## 4. `ASN1_BIT_STRING_get_bit`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L592), [a_bitstr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_bitstr.c#L184)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L96), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L170)
- Verdict: keep `not_available`
- Why: openHiTLS exposes the decoded bit-string buffer, but no dedicated public `get_bit` helper.

## 5. `ASN1_BIT_STRING_set_bit`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L591), [a_bitstr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_bitstr.c#L146)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L96), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L775)
- Verdict: keep `not_available`
- Why: openHiTLS exposes caller-managed bit-string content for encoding, but no dedicated public `set_bit` helper.

## 6. `ASN1_BIT_STRING_check`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L593), [a_bitstr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_bitstr.c#L204)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L96), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an OpenSSL-style bit-string validation helper over named-bit tables.

## 7. `ASN1_BIT_STRING_num_asc`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L598), [t_bitst.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/t_bitst.c#L47)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L96)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose the OpenSSL `BIT_STRING_BITNAME` lookup/helper family.

## 8. `ASN1_BIT_STRING_set_asc`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L599), [t_bitst.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/t_bitst.c#L33)
- openHiTLS evidence: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L96)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose the OpenSSL `BIT_STRING_BITNAME` lookup/helper family used to set named bits.

## Batch 079 summary

Keep `not_available`:
- `ASN1_BIT_STRING_free`
- `ASN1_BIT_STRING_new`
- `ASN1_BIT_STRING_set`
- `ASN1_BIT_STRING_get_bit`
- `ASN1_BIT_STRING_set_bit`
- `ASN1_BIT_STRING_check`
- `ASN1_BIT_STRING_num_asc`
- `ASN1_BIT_STRING_set_asc`

Main observation:
- openHiTLS public ASN.1 support is still struct-and-template oriented here.
- That is enough to carry bit-string payloads through encode/decode flows, but not enough to claim the OpenSSL `ASN1_BIT_STRING_*` helper family exists.
