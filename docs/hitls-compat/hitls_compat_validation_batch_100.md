# openHiTLS Compatibility Validation Batch 100

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_get_object`
- `ASN1_put_object`
- `ASN1_put_eoc`
- `ASN1_check_infinite_end`
- `ASN1_const_check_infinite_end`
- `ASN1_object_size`
- `ASN1_sign`
- `ASN1_verify`
- `ASN1_digest`
- `ASN1_dup`
- `ASN1_generate_nconf`
- `ASN1_generate_v3`
- `ASN1_mbstring_copy`
- `ASN1_mbstring_ncopy`
- `ASN1_tag2bit`
- `ASN1_tag2str`
- `ASN1_str2mask`
- `ASN1_parse`
- `ASN1_parse_dump`
- `ASN1_bn_print`
- `ASN1_buf_print`
- `ASN1_add_oid_module`
- `ASN1_add_stable_module`

Status:
- completed

Initial evidence:
- OpenSSL exposes the low-level ASN.1 helpers in `asn1.h.in:724-873` and the implementation files `asn1_lib.c:36-222`, `asn1_gen.c:78-793`, `asn1_parse.c:83-360`, `a_mbstr.c:36-42`, `t_pkey.c:21-45`, and `asn_moid.c:49`, `asn_mstbl.c:47`.
- openHiTLS public ASN.1 support remains the tag/template layer in `bsl_asn1.h:27-217` and `bsl_asn1.c:392-1607`.
- No public openHiTLS helper matches the OpenSSL tag parsing, object sizing, signing, generation, parsing, or pretty-printing helpers in this batch.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose the low-level ASN.1 object parser/formatter or the config-driven generator and mask helpers that OpenSSL publishes here.
