# openHiTLS Compatibility Validation Batch 038

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_STRING_to_UTF8`
- `ASN1_OCTET_STRING_new`
- `ASN1_STRING_set`
- `ASN1_INTEGER_set`
- `ASN1_OBJECT_free`
- `ASN1_OCTET_STRING_free`
- `ASN1_OCTET_STRING_set`
- `ASN1_TIME_to_tm`

Status:
- completed

Initial evidence:
- This is the next coherent ASN.1 helper cluster without `analysis_doc`.
- Current scan aggregation shows:
  - `ASN1_STRING_to_UTF8`: 10 repos
  - `ASN1_OCTET_STRING_new`: 8 repos
  - `ASN1_STRING_set`: 8 repos
  - `ASN1_INTEGER_set`: 7 repos
  - `ASN1_OBJECT_free`: 7 repos
  - `ASN1_OCTET_STRING_free`: 7 repos
  - `ASN1_OCTET_STRING_set`: 7 repos
  - `ASN1_TIME_to_tm`: 7 repos
- This batch confirms that openHiTLS public ASN.1 support is buffer-oriented:
  - some utility transformations exist through `BSL_ASN1_*`
  - but OpenSSL's object-allocator/object-mutator APIs do not

## 1. `ASN1_STRING_to_UTF8`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L784), [a_strex.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_strex.c#L605)
- openHiTLS declaration/implementation: [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1586)
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: `BSL_ASN1_ToUtf8String` is a public utility that performs the same broad conversion, but on `BSL_ASN1_Buffer` rather than `ASN1_STRING *`.

## 2. `ASN1_OCTET_STRING_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L637), [evp_asn1.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/evp_asn1.c#L20)
- openHiTLS public evidence: no matching allocator found in [`openhitls-upstream/include`](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an object-level octet-string allocator API.

## 3. `ASN1_STRING_set`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L577), [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L280)
- openHiTLS public evidence: no matching setter found in [`openhitls-upstream/include`](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include)
- Verdict: keep `not_available`
- Why: openHiTLS encodes ASN.1 values through generic buffers/templates, not mutable `ASN1_STRING` objects.

## 4. `ASN1_INTEGER_set`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L706), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L545)
- openHiTLS public evidence: integer encoding goes through generic `BSL_ASN1_EncodeLimb`, not an `ASN1_INTEGER` setter
- Verdict: keep `not_available`
- Why: there is no public object-level integer mutator equivalent.

## 5. `ASN1_OBJECT_free`
- OpenSSL declaration/implementation: [obj_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/objects/obj_lib.c#L52), [a_object.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_object.c#L356)
- openHiTLS public evidence: no public ASN.1 object allocator/free API in [`openhitls-upstream/include`](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose OpenSSL-style `ASN1_OBJECT` lifecycle APIs.

## 6. `ASN1_OCTET_STRING_free`
- OpenSSL declaration/implementation: [pkcs12_decr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/pkcs12/p12_decr.c#L202), [asn1_parse.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_parse.c#L353)
- openHiTLS public evidence: no public octet-string object lifecycle API
- Verdict: keep `not_available`
- Why: same object-model gap as `ASN1_OCTET_STRING_new`.

## 7. `ASN1_OCTET_STRING_set`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L637), [a_octet.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_octet.c#L25)
- openHiTLS public evidence: no public octet-string setter API
- Verdict: keep `not_available`
- Why: openHiTLS has no mutable ASN.1 octet-string object interface.

## 8. `ASN1_TIME_to_tm`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L683), [a_time.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_time.c#L441)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: `BSL_ASN1_DecodePrimitiveItem` can decode UTCTIME/GENERALIZEDTIME into `BSL_TIME`, but openHiTLS does not expose an `ASN1_TIME *` object API or a direct `struct tm` conversion helper.

## Batch 038 summary

Change to `partial`:
- `ASN1_STRING_to_UTF8`
- `ASN1_TIME_to_tm`

Keep `not_available`:
- `ASN1_OCTET_STRING_new`
- `ASN1_STRING_set`
- `ASN1_INTEGER_set`
- `ASN1_OBJECT_free`
- `ASN1_OCTET_STRING_free`
- `ASN1_OCTET_STRING_set`

Main observation:
- openHiTLS public ASN.1 support is useful but low-level and buffer-driven.
- That is enough for some utility transforms, but not for OpenSSL's object lifecycle APIs.
