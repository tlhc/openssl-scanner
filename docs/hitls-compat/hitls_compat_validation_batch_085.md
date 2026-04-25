# openHiTLS Compatibility Validation Batch 085

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_NULL_it`
- `ASN1_NULL_new`
- `ASN1_OBJECT_create`
- `ASN1_OBJECT_it`
- `ASN1_OBJECT_new`
- `ASN1_OCTET_STRING_NDEF_it`
- `ASN1_OCTET_STRING_cmp`
- `ASN1_OCTET_STRING_dup`

Status:
- completed

Initial evidence:
- `ASN1_NULL_*` remains generic-tag-only in openHiTLS.
- `ASN1_OBJECT_create` is the first OID/object-family helper with a defensible public analogue:
  - openHiTLS exposes OID registry creation and lookup helpers in `bsl_obj.h`
  - but not an `ASN1_OBJECT *` heap object API with OpenSSL semantics
- `ASN1_OCTET_STRING_*` comparison/dup/item helpers still lack a public object API.

## 1. `ASN1_NULL_it`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L44)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L39), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L849)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_NULL` ASN1_ITEM accessor.

## 2. `ASN1_NULL_new`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L44)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L39), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L563), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L849)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_NULL` object constructor.

## 3. `ASN1_OBJECT_create`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L698), [a_object.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_object.c#L380)
- openHiTLS declaration/implementation: [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L718), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L737), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L745), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L755), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L765), [bsl_obj.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/obj/src/bsl_obj.c#L569)
- Verdict: change to `partial`
- Why: openHiTLS exposes public OID registry creation and lookup helpers, but not an `ASN1_OBJECT` heap object API with OpenSSL semantics.

## 4. `ASN1_OBJECT_it`
- OpenSSL implementation: [a_object.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_object.c#L296)
- openHiTLS declaration: [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L718)
- Verdict: keep `not_available`
- Why: openHiTLS exposes registry helpers, not an `ASN1_OBJECT` ASN1_ITEM accessor.

## 5. `ASN1_OBJECT_new`
- OpenSSL implementation: [a_object.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_object.c#L343)
- openHiTLS declaration: [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L718)
- Verdict: keep `not_available`
- Why: openHiTLS exposes registry helpers, not an `ASN1_OBJECT` heap constructor.

## 6. `ASN1_OCTET_STRING_NDEF_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L674), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L70)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_OCTET_STRING_NDEF` ASN1_ITEM accessor.

## 7. `ASN1_OCTET_STRING_cmp`
- OpenSSL declaration: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L618)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_OCTET_STRING` object compare helper.

## 8. `ASN1_OCTET_STRING_dup`
- OpenSSL declaration: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L616)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_OCTET_STRING` object duplication API.

## Batch 085 summary

Change to `partial`:
- `ASN1_OBJECT_create`

Keep `not_available`:
- `ASN1_NULL_it`
- `ASN1_NULL_new`
- `ASN1_OBJECT_it`
- `ASN1_OBJECT_new`
- `ASN1_OCTET_STRING_NDEF_it`
- `ASN1_OCTET_STRING_cmp`
- `ASN1_OCTET_STRING_dup`

Main observation:
- `ASN1_OBJECT_create` is partial because openHiTLS does publish a public OID registry layer.
- That still does not generalize to OpenSSL's object constructors or ASN1_ITEM accessors.
