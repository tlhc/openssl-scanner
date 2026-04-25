# openHiTLS Compatibility Validation Batch 089

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_SEQUENCE_ANY_it`
- `ASN1_SEQUENCE_it`
- `ASN1_SET_ANY_it`
- `ASN1_STRING_TABLE_add`
- `ASN1_STRING_TABLE_cleanup`
- `ASN1_STRING_TABLE_get`
- `ASN1_STRING_clear_free`
- `ASN1_STRING_cmp`

Status:
- completed

Initial evidence:
- OpenSSL exposes sequence/set item accessors and string-table helpers through the typed ASN.1 object model.
- openHiTLS remains template-driven and does not expose the corresponding item registry or string-table registry layers.

## 1. `ASN1_SEQUENCE_ANY_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L672), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L73)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS exposes template-driven ASN.1 encode/decode, but no `ASN1_ITEM` accessor for `ASN1_SEQUENCE_ANY`.

## 2. `ASN1_SEQUENCE_it`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L50)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS exposes template-driven ASN.1 encode/decode, but no `ASN1_ITEM` accessor for `ASN1_SEQUENCE`.

## 3. `ASN1_SET_ANY_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L672), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L74)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS exposes template-driven ASN.1 encode/decode, but no `ASN1_ITEM` accessor for `ASN1_SET_ANY`.

## 4. `ASN1_STRING_TABLE_add`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L849), [a_strnid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_strnid.c#L185)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose OpenSSL's `ASN1_STRING_TABLE` registry layer.

## 5. `ASN1_STRING_TABLE_cleanup`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L850), [a_strnid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_strnid.c#L207)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose OpenSSL's `ASN1_STRING_TABLE` registry layer.

## 6. `ASN1_STRING_TABLE_get`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L848), [a_strnid.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_strnid.c#L127)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose OpenSSL's `ASN1_STRING_TABLE` registry layer.

## 7. `ASN1_STRING_clear_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L568), [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L376)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_STRING` object lifecycle API.

## 8. `ASN1_STRING_cmp`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L572), [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L385)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_STRING` compare helper.

## Batch 089 summary

Keep `not_available`:
- `ASN1_SEQUENCE_ANY_it`
- `ASN1_SEQUENCE_it`
- `ASN1_SET_ANY_it`
- `ASN1_STRING_TABLE_add`
- `ASN1_STRING_TABLE_cleanup`
- `ASN1_STRING_TABLE_get`
- `ASN1_STRING_clear_free`
- `ASN1_STRING_cmp`

Main observation:
- This batch is blocked by two absent layers on the openHiTLS public surface:
  - no item-registry accessors for SEQUENCE/SET wrappers
  - no string-table registry helpers
