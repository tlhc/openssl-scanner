# openHiTLS Compatibility Validation Batch 090

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_STRING_copy`
- `ASN1_STRING_dup`
- `ASN1_STRING_free`
- `ASN1_STRING_get_default_mask`
- `ASN1_STRING_length_set`
- `ASN1_STRING_new`
- `ASN1_STRING_print`
- `ASN1_STRING_print_ex`

Status:
- completed

Initial evidence:
- OpenSSL exposes the mutable `ASN1_STRING` object family in [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L562) and [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L376).
- openHiTLS public ASN.1 support exposes generic `BSL_ASN1_Buffer` and template encode/decode only: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196).
- The only narrow public string-side analogue found so far remains `ASN1_STRING_to_UTF8` from batch 038; none of the object/lifecycle/printing helpers in this batch have a public match.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose the OpenSSL `ASN1_STRING` object model, so copy/dup/free/new/mask/print helpers do not have public analogues at the truth-library boundary.
