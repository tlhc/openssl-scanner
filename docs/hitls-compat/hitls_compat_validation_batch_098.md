# openHiTLS Compatibility Validation Batch 098

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_TYPE_cmp`
- `ASN1_TYPE_free`
- `ASN1_TYPE_get`
- `ASN1_TYPE_get_int_octetstring`
- `ASN1_TYPE_get_octetstring`
- `ASN1_TYPE_new`
- `ASN1_TYPE_pack_sequence`
- `ASN1_TYPE_set`
- `ASN1_TYPE_set1`
- `ASN1_TYPE_set_int_octetstring`
- `ASN1_TYPE_set_octetstring`
- `ASN1_TYPE_unpack_sequence`

Status:
- completed

Initial evidence:
- OpenSSL exposes `ASN1_TYPE` object helpers in `asn1.h.in:552-558`, `asn1.h.in:824-828`, and `a_type.c:16-137`, with octetstring packing helpers in `evp_asn1.c:16-174`.
- openHiTLS public ASN.1 support only exposes tag constants, primitive decode helpers, and template encode/decode helpers in `bsl_asn1.h:27-217`.
- There is no public openHiTLS `ASN1_TYPE` object API.

Verdict:
- keep `not_available` for all `ASN1_TYPE_*` entries in scope.

Why:
- openHiTLS uses raw `BSL_ASN1_Buffer` plus template-based encode/decode rather than OpenSSL-style `ASN1_TYPE` object constructors, setters, getters, or pack/unpack helpers.
