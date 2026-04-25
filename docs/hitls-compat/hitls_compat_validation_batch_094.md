# openHiTLS Compatibility Validation Batch 094

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_TIME_set_string`
- `ASN1_TIME_set_string_X509`
- `ASN1_TIME_to_generalizedtime`
- `ASN1_UTCTIME_adj`
- `ASN1_UTCTIME_check`
- `ASN1_UTCTIME_cmp_time_t`
- `ASN1_UTCTIME_dup`
- `ASN1_UTCTIME_free`

Status:
- completed

Initial evidence:
- openHiTLS public time support for UTCTIME mirrors the earlier GENERALIZEDTIME/TIME pattern:
  - decode `UTCTIME` into `BSL_TIME`
  - validate through `BSL_DateTimeCheck`
  - convert UTC time through `BSL_SAL_UtcTimeToDateConvert`
  - compare via `BSL_SAL_DateTimeCompare`
  - encode caller-owned `BSL_TIME` under the `UTCTIME` tag with `BSL_ASN1_EncodeTemplate`
- That supports narrow composed analogues for `adj/check/cmp_time_t`, but not the object-layer helpers.

## Verdict

Change to `partial`:
- `ASN1_UTCTIME_adj`
- `ASN1_UTCTIME_check`
- `ASN1_UTCTIME_cmp_time_t`

Keep `not_available`:
- `ASN1_TIME_set_string`
- `ASN1_TIME_set_string_X509`
- `ASN1_TIME_to_generalizedtime`
- `ASN1_UTCTIME_dup`
- `ASN1_UTCTIME_free`

Why:
- openHiTLS has no `ASN1_TIME *` / `ASN1_UTCTIME *` object family, but it does publish enough `BSL_TIME` and ASN.1 template primitives to justify narrow buffer-based analogues for validation and comparison helpers.
