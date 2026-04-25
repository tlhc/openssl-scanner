# openHiTLS Compatibility Validation Batch 084

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_INTEGER_get_int64`
- `ASN1_INTEGER_get_uint64`
- `ASN1_INTEGER_it`
- `ASN1_INTEGER_new`
- `ASN1_INTEGER_set_int64`
- `ASN1_INTEGER_set_uint64`
- `ASN1_INTEGER_to_BN`
- `ASN1_NULL_free`

Status:
- completed

Initial evidence:
- openHiTLS public ASN.1 INTEGER support is still primitive-buffer based:
  - decode: `BSL_ASN1_DecodePrimitiveItem(BSL_ASN1_TAG_INTEGER -> int)`
  - encode: `BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, ...)`
- That is not enough to claim the `ASN1_INTEGER` object lifecycle or wide-width getter/setter family.
- `NULL` is likewise handled only as a generic tag inside template encode/decode flows.

## 1. `ASN1_INTEGER_get_int64`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L701), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L525)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
- Verdict: keep `not_available`
- Why: openHiTLS primitive INTEGER decoding goes through `ParseInt` with `int`-sized output, not an `int64` getter.

## 2. `ASN1_INTEGER_get_uint64`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L703), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L535)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
- Verdict: keep `not_available`
- Why: openHiTLS primitive INTEGER decoding goes through `ParseInt` with `int`-sized output, not a `uint64` getter.

## 3. `ASN1_INTEGER_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L606), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L29)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174)
- Verdict: keep `not_available`
- Why: openHiTLS exposes INTEGER only as a primitive tag in buffer/template APIs, not as an `ASN1_ITEM` accessor.

## 4. `ASN1_INTEGER_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L606), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L29), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L299)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1389)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_INTEGER` object constructor.

## 5. `ASN1_INTEGER_set_int64`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L702), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L530)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1389)
- Verdict: keep `not_available`
- Why: `BSL_ASN1_EncodeLimb` is a caller-buffer encoder, not an `ASN1_INTEGER` object setter.

## 6. `ASN1_INTEGER_set_uint64`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L704), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L540)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1389)
- Verdict: keep `not_available`
- Why: `BSL_ASN1_EncodeLimb` is a caller-buffer encoder, not an `ASN1_INTEGER` object setter.

## 7. `ASN1_INTEGER_to_BN`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L709), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L569)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L36), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public `ASN1_INTEGER -> BN` conversion API.

## 8. `ASN1_NULL_free`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L44)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L39), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L563), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L849)
- Verdict: keep `not_available`
- Why: openHiTLS handles `NULL` as a generic tag in buffer/template flows, not as an `ASN1_NULL` object lifecycle API.

## Batch 084 summary

Keep `not_available`:
- `ASN1_INTEGER_get_int64`
- `ASN1_INTEGER_get_uint64`
- `ASN1_INTEGER_it`
- `ASN1_INTEGER_new`
- `ASN1_INTEGER_set_int64`
- `ASN1_INTEGER_set_uint64`
- `ASN1_INTEGER_to_BN`
- `ASN1_NULL_free`

Main observation:
- The boundary remains the same: primitive INTEGER encode/decode exists publicly, but not the OpenSSL object-layer helper family.
