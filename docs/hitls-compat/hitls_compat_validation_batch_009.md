# openHiTLS Compatibility Validation Batch 009

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `sk_X509_num`
- `sk_X509_value`
- `sk_X509_pop_free`
- `sk_X509_push`
- `ASN1_SIMPLE`
- `ASN1_EXP_OPT`
- `ASN1_SEQUENCE_END`
- `ASN1_STRING_length`
- `ASN1_STRING_get0_data`
- `ASN1_TIME_print`
- `ASN1_STRING_data`

Status:
- completed

Initial evidence:
- OpenSSL usage for stack helpers is widespread in X509/CMS/OCSP paths, for example [x509_vfy.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_vfy.c#L186), [pk7_smime.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/pkcs7/pk7_smime.c#L435), and [store_result.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/store/store_result.c#L630).
- OpenSSL ASN.1 string/time helpers are public in [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L579), [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L587), [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L808), with implementations in [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L402) and [a_time.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_time.c#L474).
- openHiTLS exposes generic list operations publicly through [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L124), [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L149), [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L197), [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L474), and [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L491).
- openHiTLS already has `ASN1_STRING_*` and `ASN1_TIME_print` marked `not_available`; the open question is whether any public PKI print or list APIs are function-level substitutes or whether the current `not_available` verdict is correct for the truth-library boundary.

Key questions for this batch:
- whether `sk_X509_*` helpers should map to generic `BSL_LIST_*` APIs or stay `partial` because type system, ownership, and list node contracts differ,
- and whether any public PKI print/string utilities justify changing the current `ASN1_*` helper verdicts from `not_available`.

## 1. `sk_X509_num`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro: [x509.h](openssl-3.0.9/include/openssl/x509.h:76)
- openHiTLS list alias: [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L32)
- openHiTLS count macro: [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L124)

Verdict:
- Add as `available`

Why:
- `HITLS_X509_List` is a public alias of `BslList`.
- `BSL_LIST_COUNT` is the direct public count macro.

## 2. `sk_X509_value`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro: [x509.h](openssl-3.0.9/include/openssl/x509.h:77)
- openHiTLS index accessor declaration: [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L263)
- openHiTLS implementation: [bsl_list.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/list/src/bsl_list.c#L356)

Verdict:
- Add as `partial`

Why:
- `BSL_LIST_GetIndexNode(index, list)` is the closest public helper.
- Unlike OpenSSL `OPENSSL_sk_value`, it advances the list's public `curr` cursor while searching, so it is not a semantics-preserving drop-in.

## 3. `sk_X509_pop_free`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro: [x509.h](openssl-3.0.9/include/openssl/x509.h:90)
- openHiTLS free macro: [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L149)
- openHiTLS delete-all implementation: [bsl_list.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/list/src/bsl_list.c#L188)

Verdict:
- Add as `available`

Why:
- `BSL_LIST_FREE(list, freefunc)` is the direct public “free all nodes and header” operation.
- It matches the ownership role of `sk_X509_pop_free`.

## 4. `sk_X509_push`

Current JSON:
- missing

Verified evidence:
- OpenSSL macro: [x509.h](openssl-3.0.9/include/openssl/x509.h:86)
- openHiTLS alias: [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L32)
- openHiTLS push helper: [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L197)
- openHiTLS implementation: [bsl_list.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/list/src/bsl_list.c#L150)

Verdict:
- Add as `partial`

Why:
- `BSL_LIST_AddElement(list, item, BSL_LIST_POS_END)` is the nearest public append operation.
- It mutates the list's public `curr` cursor and uses a generic list-position API, so it is not a clean drop-in for OpenSSL stack push.

## 5. `ASN1_SIMPLE`

Current JSON:
- missing

Verified evidence:
- OpenSSL use-site class: ASN.1 template DSL macro, not runtime function
- openHiTLS public template system: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L77), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)

Verdict:
- Add as `not_available`

Why:
- openHiTLS exposes explicit ASN.1 template structs and encode/decode functions.
- It does not expose an OpenSSL-style compile-time macro DSL equivalent.

## 6. `ASN1_EXP_OPT`

Verdict:
- Add as `not_available`

Why:
- Same rationale as `ASN1_SIMPLE`.

## 7. `ASN1_SEQUENCE_END`

Verdict:
- Add as `not_available`

Why:
- Same rationale as `ASN1_SIMPLE`.

## 8. `ASN1_STRING_length`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L579), [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L402)
- openHiTLS public ASN.1 surface: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L90)

Verdict:
- Keep `not_available`

Why:
- openHiTLS exposes raw `BSL_ASN1_Buffer.len`, not an `ASN1_STRING` object API with dedicated getter.

## 9. `ASN1_STRING_get0_data`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L587), [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L419)
- openHiTLS public ASN.1 surface: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L90)

Verdict:
- Keep `not_available`

Why:
- Same reason as `ASN1_STRING_length`: no public `ASN1_STRING` object API exists.

## 10. `ASN1_TIME_print`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L808), [a_time.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_time.c#L474)
- openHiTLS public print cmd set: [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L390), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L395)
- openHiTLS print entry point: [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L45), [hitls_pki_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/print/src/hitls_pki_print.c#L1165)

Verdict:
- Keep `not_available`

Why:
- openHiTLS can print `BSL_TIME` or higher-level PKI structures, but it does not expose a public `ASN1_TIME` type or direct `ASN1_TIME_print` equivalent.

## 11. `ASN1_STRING_data`

Current JSON:
- `status = not_available`

Verified evidence:
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L585), [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L425)
- openHiTLS public ASN.1 surface: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L90)

Verdict:
- Keep `not_available`

Why:
- Same reason as `ASN1_STRING_get0_data`.

## Batch 009 summary

Add:
- `sk_X509_num`: `available`
- `sk_X509_value`: `partial`
- `sk_X509_pop_free`: `available`
- `sk_X509_push`: `partial`
- `ASN1_SIMPLE`: `not_available`
- `ASN1_EXP_OPT`: `not_available`
- `ASN1_SEQUENCE_END`: `not_available`

Keep:
- `ASN1_STRING_length`
- `ASN1_STRING_get0_data`
- `ASN1_TIME_print`
- `ASN1_STRING_data`

Main observation:
- openHiTLS has a solid public generic list API that can cover part of the OpenSSL `sk_X509_*` helper surface.
- It still does not expose OpenSSL-style low-level ASN.1 object helper APIs or macro DSLs as public compatibility primitives.
