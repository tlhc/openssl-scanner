# openHiTLS Compatibility Validation Batch 095

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_UTCTIME_it`
- `ASN1_UTCTIME_new`
- `ASN1_UTCTIME_print`
- `ASN1_UTCTIME_set`
- `ASN1_UTCTIME_set_string`
- `ASN1_UTF8STRING_free`
- `ASN1_UTF8STRING_it`
- `ASN1_UTF8STRING_new`

Status:
- completed

Initial evidence:
- openHiTLS public UTCTIME support can:
  - decode ASN.1 UTCTIME into `BSL_TIME`
  - print `BSL_TIME` through `BSL_PRINT_Time`
  - encode caller-owned `BSL_TIME` back under the `UTCTIME` tag
- That is enough for narrow composed analogues on `print` and `set`, but not for object lifecycle or string-parsing helpers.

## Verdict

Change to `partial`:
- `ASN1_UTCTIME_print`
- `ASN1_UTCTIME_set`

Keep `not_available`:
- `ASN1_UTCTIME_it`
- `ASN1_UTCTIME_new`
- `ASN1_UTCTIME_set_string`
- `ASN1_UTF8STRING_free`
- `ASN1_UTF8STRING_it`
- `ASN1_UTF8STRING_new`

Why:
- openHiTLS has no `ASN1_UTCTIME *` / `ASN1_UTF8STRING *` object family, but it does publish enough `BSL_TIME` and template primitives to justify the narrow buffer-based analogues on `print` and `set`.
