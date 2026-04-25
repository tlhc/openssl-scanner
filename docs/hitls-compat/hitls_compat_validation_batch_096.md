# openHiTLS Compatibility Validation Batch 096

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_UNIVERSALSTRING_free`
- `ASN1_UNIVERSALSTRING_it`
- `ASN1_UNIVERSALSTRING_new`
- `ASN1_UNIVERSALSTRING_to_string`
- `ASN1_VISIBLESTRING_free`
- `ASN1_VISIBLESTRING_it`
- `ASN1_VISIBLESTRING_new`

Status:
- completed

Initial evidence:
- openHiTLS public ASN.1 support exposes string tags such as `BSL_ASN1_TAG_UNIVERSALSTRING` and generic buffer/template encode/decode helpers.
- It does not expose the typed OpenSSL object families for `ASN1_UNIVERSALSTRING *` or `ASN1_VISIBLESTRING *`.
- The closest UTF-8 conversion path remains internal-only and is not a public typed API.

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose typed lifecycle, ASN1_ITEM, constructor, or direct string-conversion helpers for these string families at the truth-library boundary.
