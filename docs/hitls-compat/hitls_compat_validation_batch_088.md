# openHiTLS Compatibility Validation Batch 088

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_PRINTABLE_free`
- `ASN1_PRINTABLE_it`
- `ASN1_PRINTABLE_new`
- `ASN1_PRINTABLE_type`
- `ASN1_SCTX_free`
- `ASN1_SCTX_get_app_data`
- `ASN1_SCTX_get_flags`
- `ASN1_SCTX_get_item`
- `ASN1_SCTX_get_template`
- `ASN1_SCTX_new`
- `ASN1_SCTX_set_app_data`

Status:
- completed

Initial evidence:
- `ASN1_PRINTABLE*` is the multi-string wrapper side of the same typed-string gap already seen elsewhere.
- `ASN1_SCTX_*` is the scan-context family; OpenSSL exposes it publicly, openHiTLS does not.

## 1. `ASN1_PRINTABLE_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L657), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L57)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L51)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_PRINTABLE` object lifecycle API.

## 2. `ASN1_PRINTABLE_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L657), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L57)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L51)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_PRINTABLE` ASN1_ITEM accessor.

## 3. `ASN1_PRINTABLE_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L657), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L57)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L51)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_PRINTABLE` object constructor.

## 4. `ASN1_PRINTABLE_type`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L722), [a_print.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_print.c#L15)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L51), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1561)
- Verdict: keep `not_available`
- Why: openHiTLS exposes generic string-conversion helpers, but no public classifier equivalent to `ASN1_PRINTABLE_type`.

## 5. `ASN1_SCTX_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L912), [tasn_scn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_scn.c#L37)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS has no public ASN1 scan-context object.

## 6. `ASN1_SCTX_get_app_data`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L917), [tasn_scn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_scn.c#L62)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS has no public ASN1 scan-context object.

## 7. `ASN1_SCTX_get_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L915), [tasn_scn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_scn.c#L52)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS has no public ASN1 scan-context object.

## 8. `ASN1_SCTX_get_item`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L913), [tasn_scn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_scn.c#L42)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS has no public ASN1 scan-context object.

## 9. `ASN1_SCTX_get_template`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L914), [tasn_scn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_scn.c#L47)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS has no public ASN1 scan-context object.

## 10. `ASN1_SCTX_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L911), [tasn_scn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_scn.c#L25)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS has no public ASN1 scan-context object.

## 11. `ASN1_SCTX_set_app_data`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L916), [tasn_scn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_scn.c#L57)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS has no public ASN1 scan-context object.

## Batch 088 summary

Keep `not_available`:
- `ASN1_PRINTABLE_free`
- `ASN1_PRINTABLE_it`
- `ASN1_PRINTABLE_new`
- `ASN1_PRINTABLE_type`
- `ASN1_SCTX_free`
- `ASN1_SCTX_get_app_data`
- `ASN1_SCTX_get_flags`
- `ASN1_SCTX_get_item`
- `ASN1_SCTX_get_template`
- `ASN1_SCTX_new`
- `ASN1_SCTX_set_app_data`

Main observation:
- This batch combines the remaining absent `ASN1_PRINTABLE*` wrappers and the absent `ASN1_SCTX*` scan-context family.
