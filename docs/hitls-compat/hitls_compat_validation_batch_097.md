# openHiTLS Compatibility Validation Batch 097

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_ANY_it`
- `ASN1_BIT_STRING_it`
- `ASN1_BIT_STRING_name_print`

Status:
- completed

Initial evidence:
- OpenSSL exposes typed item accessors and named-bit printing helpers on top of its object model.
- openHiTLS exposes:
  - `ANY` only through template callback handling
  - `BIT STRING` only through `BSL_ASN1_BitString`
  - no public named-bit print helper family

Verdict:
- keep `not_available` for all entries in scope.

Why:
- openHiTLS does not expose OpenSSL-style `ASN1_ITEM` accessors for `ANY` / `BIT STRING`, and it does not expose the named-bit printing helper family.
