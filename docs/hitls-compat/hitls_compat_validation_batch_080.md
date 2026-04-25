# openHiTLS Compatibility Validation Batch 080

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_BMPSTRING_free`
- `ASN1_BMPSTRING_it`
- `ASN1_BMPSTRING_new`
- `ASN1_BOOLEAN_it`
- `ASN1_ENUMERATED_free`
- `ASN1_ENUMERATED_get`
- `ASN1_ENUMERATED_get_int64`
- `ASN1_ENUMERATED_it`

Status:
- completed

Initial evidence:
- openHiTLS public ASN.1 support continues to be primitive-buffer oriented rather than object oriented.
- Relevant public pieces found here:
  - `BSL_ASN1_TAG_BMPSTRING`
  - `BSL_ASN1_TAG_BOOLEAN`
  - `BSL_ASN1_TAG_ENUMERATED`
  - `BSL_ASN1_DecodePrimitiveItem`
  - `BSL_ASN1_EncodeLimb`
- The key distinction is whether that primitive support is enough to claim a public analogue for an OpenSSL helper. For `ASN1_ENUMERATED_get`, it is. For object lifecycle and `*_it`, it is not.

## 1. `ASN1_BMPSTRING_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L648), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L41)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L59), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392), [hitls_pkcs12_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/pkcs12/src/hitls_pkcs12_common.c#L213)
- Verdict: keep `not_available`
- Why: openHiTLS can decode BMPSTRING content into a buffer, but it does not expose an `ASN1_BMPSTRING` object lifecycle API.

## 2. `ASN1_BMPSTRING_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L648), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L41)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L59)
- Verdict: keep `not_available`
- Why: openHiTLS exposes BMPSTRING only as a primitive tag inside buffer/template APIs, not as an OpenSSL-style `ASN1_ITEM` accessor.

## 3. `ASN1_BMPSTRING_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L648), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L41)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L59), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392), [hitls_pkcs12_common.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/pkcs12/src/hitls_pkcs12_common.c#L213)
- Verdict: keep `not_available`
- Why: openHiTLS has no public `ASN1_BMPSTRING` object constructor.

## 4. `ASN1_BOOLEAN_it`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L67)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L35), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L184), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L164), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L397), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L202)
- Verdict: keep `not_available`
- Why: openHiTLS exposes BOOLEAN only as a primitive tag decoded into `bool`, not as an OpenSSL-style `ASN1_ITEM` accessor.

## 5. `ASN1_ENUMERATED_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L613), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L30), [asn1_parse.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_parse.c#L355)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392), [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L1355)
- Verdict: keep `not_available`
- Why: openHiTLS can decode enumerated values from buffers, but it does not expose an `ASN1_ENUMERATED` object lifecycle API.

## 6. `ASN1_ENUMERATED_get`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L716), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L589)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392), [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L1355)
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can decode a public ASN.1 `ENUMERATED` buffer into an `int` through `BSL_ASN1_DecodePrimitiveItem`, but it does not expose an `ASN1_ENUMERATED *` object API.

## 7. `ASN1_ENUMERATED_get_int64`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L711), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L574)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
- Verdict: keep `not_available`
- Why: openHiTLS primitive `ENUMERATED` decoding goes through `ParseInt` with `int`-sized output, not an `int64`-capable getter.

## 8. `ASN1_ENUMERATED_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L613), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L30)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174)
- Verdict: keep `not_available`
- Why: openHiTLS exposes `ENUMERATED` only as a primitive ASN.1 tag in buffer/template APIs, not as an OpenSSL-style `ASN1_ITEM` accessor.

## Batch 080 summary

Change to `partial`:
- `ASN1_ENUMERATED_get`

Keep `not_available`:
- `ASN1_BMPSTRING_free`
- `ASN1_BMPSTRING_it`
- `ASN1_BMPSTRING_new`
- `ASN1_BOOLEAN_it`
- `ASN1_ENUMERATED_free`
- `ASN1_ENUMERATED_get_int64`
- `ASN1_ENUMERATED_it`

Main observation:
- This batch is the first ASN.1 simple-type cluster where a getter crosses the threshold into `partial`.
- The reason is narrow and explicit: public buffer-based decode exists for `ENUMERATED -> int`, but the broader OpenSSL object/helper family still does not.
