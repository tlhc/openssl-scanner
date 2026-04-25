# openHiTLS Compatibility Validation Batch 099

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_ANY_it`
- `ASN1_SEQUENCE_ANY_it`
- `ASN1_SEQUENCE_it`
- `ASN1_SET_ANY_it`
- `ASN1_ITEM_get`
- `ASN1_ITEM_lookup`
- `ASN1_d2i_bio`
- `ASN1_i2d_bio`
- `ASN1_item_d2i`
- `ASN1_item_d2i_bio`
- `ASN1_item_d2i_bio_ex`
- `ASN1_item_d2i_ex`
- `ASN1_item_d2i_fp`
- `ASN1_item_d2i_fp_ex`
- `ASN1_item_digest`
- `ASN1_item_dup`
- `ASN1_item_ex_d2i`
- `ASN1_item_ex_free`
- `ASN1_item_ex_i2d`
- `ASN1_item_ex_new`
- `ASN1_item_free`
- `ASN1_item_i2d`
- `ASN1_item_i2d_bio`
- `ASN1_item_i2d_fp`
- `ASN1_item_i2d_mem_bio`
- `ASN1_item_ndef_i2d`
- `ASN1_item_new`
- `ASN1_item_new_ex`
- `ASN1_item_pack`
- `ASN1_item_print`
- `ASN1_item_sign`
- `ASN1_item_sign_ctx`
- `ASN1_item_sign_ex`
- `ASN1_item_unpack`
- `ASN1_item_unpack_ex`
- `ASN1_item_verify`
- `ASN1_item_verify_ctx`
- `ASN1_item_verify_ex`

Status:
- completed

Initial evidence:
- OpenSSL exposes the item registry and item-based d2i/i2d helpers in `asn1.h.in:943-944`, `asn1.h.in:786-805`, `asn1.h.in:831-864`, and the supporting implementations in `a_d2i_fp.c:38-103`, `tasn_dec.c:120-149`, `tasn_enc.c:43-83`, `a_digest.c:28-89`, `a_dup.c:16-85`, `a_verify.c:27-112`, and `asn_pack.c:16-59`.
- openHiTLS public ASN.1 support is template-driven: `BSL_ASN1_DecodeTemplate` in `bsl_asn1.c:686-757` and `BSL_ASN1_EncodeTemplate` in `bsl_asn1.c:1286-1315`.
- openHiTLS has no public `ASN1_ITEM` registry or BIO/FILE item wrappers.

Verdict:
- `ASN1_item_d2i`: keep `partial`
- `ASN1_item_i2d`: keep `partial`
- all remaining item helpers in scope: keep `not_available`

Why:
- openHiTLS can decode and encode through explicit templates, which is close enough to justify the narrow `partial` on `ASN1_item_d2i` and `ASN1_item_i2d`, but it does not expose the OpenSSL item registry, BIO/FILE wrappers, pack/unpack helpers, or sign/verify helpers.
