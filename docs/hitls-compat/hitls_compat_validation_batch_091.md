# openHiTLS Compatibility Validation Batch 091

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_STRING_print_ex_fp`
- `ASN1_STRING_set0`
- `ASN1_STRING_set_by_NID`
- `ASN1_STRING_set_default_mask`
- `ASN1_STRING_set_default_mask_asc`
- `ASN1_STRING_type`
- `ASN1_STRING_type_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes these helpers on top of the mutable `ASN1_STRING` object family in [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L562), [asn1_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/asn1_lib.c#L376), and [a_mbstr.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_mbstr.c#L36).
- openHiTLS public ASN.1 support remains generic-buffer oriented via [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), and [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196).

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose the OpenSSL `ASN1_STRING` object model, so setter/type/mask/FILE-print helpers do not have public analogues at the truth-library boundary.
