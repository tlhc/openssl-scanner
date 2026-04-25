# openHiTLS Compatibility Validation Batch 087

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_PCTX_set_cert_flags`
- `ASN1_PCTX_set_flags`
- `ASN1_PCTX_set_nm_flags`
- `ASN1_PCTX_set_oid_flags`
- `ASN1_PCTX_set_str_flags`
- `ASN1_PRINTABLESTRING_free`
- `ASN1_PRINTABLESTRING_it`
- `ASN1_PRINTABLESTRING_new`

Status:
- completed

Initial evidence:
- `ASN1_PCTX_set_*` is the mutator half of the printer-context family already established as absent on the openHiTLS public surface.
- `ASN1_PRINTABLESTRING_*` sits on the same boundary as other simple ASN.1 string object families:
  - openHiTLS exposes primitive tags and generic conversion
  - but not OpenSSL-style typed object constructors/lifecycle APIs

## 1. `ASN1_PCTX_set_cert_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L905), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L77)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 2. `ASN1_PCTX_set_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L901), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L57)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 3. `ASN1_PCTX_set_nm_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L903), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L67)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 4. `ASN1_PCTX_set_oid_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L907), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L87)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 5. `ASN1_PCTX_set_str_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L909), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L97)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 6. `ASN1_PRINTABLESTRING_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L661), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L33)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L51), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1564)
- Verdict: keep `not_available`
- Why: openHiTLS exposes PRINTABLESTRING only as a primitive tag in generic buffer/template flows, not as an object lifecycle API.

## 7. `ASN1_PRINTABLESTRING_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L661), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L33)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L51)
- Verdict: keep `not_available`
- Why: openHiTLS exposes PRINTABLESTRING only as a primitive tag, not as an ASN1_ITEM accessor.

## 8. `ASN1_PRINTABLESTRING_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L661), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L33)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L51), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1564)
- Verdict: keep `not_available`
- Why: openHiTLS exposes PRINTABLESTRING only as a primitive tag, not as an object constructor.

## Batch 087 summary

Keep `not_available`:
- `ASN1_PCTX_set_cert_flags`
- `ASN1_PCTX_set_flags`
- `ASN1_PCTX_set_nm_flags`
- `ASN1_PCTX_set_oid_flags`
- `ASN1_PCTX_set_str_flags`
- `ASN1_PRINTABLESTRING_free`
- `ASN1_PRINTABLESTRING_it`
- `ASN1_PRINTABLESTRING_new`

Main observation:
- This batch combines two different absent surfaces:
  - no public `ASN1_PCTX` object layer
  - no typed `ASN1_PRINTABLESTRING` object family
