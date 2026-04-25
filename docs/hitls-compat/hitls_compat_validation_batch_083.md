# openHiTLS Compatibility Validation Batch 083

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_GENERALSTRING_new`
- `ASN1_IA5STRING_free`
- `ASN1_IA5STRING_it`
- `ASN1_IA5STRING_new`
- `ASN1_INTEGER_cmp`
- `ASN1_INTEGER_dup`
- `ASN1_INTEGER_free`
- `ASN1_INTEGER_get`

Status:
- completed

Initial evidence:
- `IA5STRING` and `GENERALSTRING` remain in the same bucket as other simple ASN.1 string types: generic primitive-tag handling exists, but no OpenSSL-style object API family.
- `ASN1_INTEGER_get` crosses the same threshold as `ASN1_ENUMERATED_get`: openHiTLS can decode a public INTEGER buffer into an `int` through `BSL_ASN1_DecodePrimitiveItem`.

## 1. `ASN1_GENERALSTRING_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L664), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L36)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_GENERALSTRING` object constructor.

## 2. `ASN1_IA5STRING_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L663), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L35)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L54), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1565)
- Verdict: keep `not_available`
- Why: openHiTLS exposes IA5STRING only as a primitive tag in generic buffer/template flows, not as an object lifecycle API.

## 3. `ASN1_IA5STRING_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L663), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L35)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L54)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_ITEM` accessor for IA5STRING.

## 4. `ASN1_IA5STRING_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L663), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L35)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L54), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1565)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an IA5STRING object constructor.

## 5. `ASN1_INTEGER_cmp`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L611), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L23)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
- Verdict: keep `not_available`
- Why: openHiTLS can decode INTEGER into `int`-sized primitives, but does not expose an `ASN1_INTEGER` object compare helper.

## 6. `ASN1_INTEGER_dup`
- OpenSSL implementation: [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L18)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_INTEGER` object duplication API.

## 7. `ASN1_INTEGER_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L609), [asn1_parse.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_parse.c#L354)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1389)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_INTEGER` object lifecycle API.

## 8. `ASN1_INTEGER_get`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L707), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L550)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392), [hitls_pkcs12_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/pkcs12/src/hitls_pkcs12_common.c#L761)
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can decode a public ASN.1 INTEGER buffer into an `int` through `BSL_ASN1_DecodePrimitiveItem`, but it does not expose an `ASN1_INTEGER` object API.

## Batch 083 summary

Change to `partial`:
- `ASN1_INTEGER_get`

Keep `not_available`:
- `ASN1_GENERALSTRING_new`
- `ASN1_IA5STRING_free`
- `ASN1_IA5STRING_it`
- `ASN1_IA5STRING_new`
- `ASN1_INTEGER_cmp`
- `ASN1_INTEGER_dup`
- `ASN1_INTEGER_free`

Main observation:
- `INTEGER_get` follows the same narrow upgrade rule as `ENUMERATED_get`.
- The rest of the family still lacks object lifecycle / item-accessor equivalents.
