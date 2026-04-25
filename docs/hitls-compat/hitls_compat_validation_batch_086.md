# openHiTLS Compatibility Validation Batch 086

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_OCTET_STRING_it`
- `ASN1_PCTX_free`
- `ASN1_PCTX_get_cert_flags`
- `ASN1_PCTX_get_flags`
- `ASN1_PCTX_get_nm_flags`
- `ASN1_PCTX_get_oid_flags`
- `ASN1_PCTX_get_str_flags`
- `ASN1_PCTX_new`

Status:
- completed

Initial evidence:
- OpenSSL exposes a public ASN1 printer-context object in `asn1.h.in:898-909` and `tasn_prn.c:35-97`.
- openHiTLS public ASN.1 support remains tag/template oriented:
  - `BSL_ASN1_Buffer`
  - `BSL_ASN1_Template`
  - `BSL_ASN1_DecodeTemplate`
  - `BSL_ASN1_EncodeTemplate`
- There is no public openHiTLS `ASN1_PCTX` object layer to map these helpers onto.

## 1. `ASN1_OCTET_STRING_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L633), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L28)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS exposes OCTET STRING only as a primitive tag in generic buffer/template flows, not as an ASN1_ITEM accessor.

## 2. `ASN1_PCTX_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L899), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L47)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 3. `ASN1_PCTX_get_cert_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L904), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L72)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 4. `ASN1_PCTX_get_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L900), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L52)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 5. `ASN1_PCTX_get_nm_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L902), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L62)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 6. `ASN1_PCTX_get_oid_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L906), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L82)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 7. `ASN1_PCTX_get_str_flags`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L908), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L92)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## 8. `ASN1_PCTX_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L898), [tasn_prn.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_prn.c#L35)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L85), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public ASN1 printer-context object.

## Batch 086 summary

Keep `not_available`:
- `ASN1_OCTET_STRING_it`
- `ASN1_PCTX_free`
- `ASN1_PCTX_get_cert_flags`
- `ASN1_PCTX_get_flags`
- `ASN1_PCTX_get_nm_flags`
- `ASN1_PCTX_get_oid_flags`
- `ASN1_PCTX_get_str_flags`
- `ASN1_PCTX_new`

Main observation:
- This entire batch is blocked by the same absence: openHiTLS has no public printer-context object layer.
