# openHiTLS Compatibility Validation Batch 092

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_T61STRING_free`
- `ASN1_T61STRING_it`
- `ASN1_T61STRING_new`
- `ASN1_TBOOLEAN_it`
- `ASN1_TIME_adj`
- `ASN1_TIME_check`
- `ASN1_TIME_cmp_time_t`
- `ASN1_TIME_compare`

Status:
- completed

Initial evidence:
- openHiTLS exposes T61/Teletex only as a primitive tag in the generic ASN.1 conversion pipeline.
- For time helpers, openHiTLS publishes a usable composed public path:
  - ASN.1 decode into `BSL_TIME`
  - `BSL_DateTimeCheck`
  - `BSL_SAL_UtcTimeToDateConvert`
  - `BSL_SAL_DateTimeCompare`
  - `BSL_DateTimeAddDaySecond`
  - `BSL_ASN1_EncodeTemplate` with `BSL_ASN1_TAG_UTCTIME` or `BSL_ASN1_TAG_GENERALIZEDTIME`

## 1. `ASN1_T61STRING_free`
- Verdict: keep `not_available`
- Why: openHiTLS has no typed T61STRING object lifecycle API.

## 2. `ASN1_T61STRING_it`
- Verdict: keep `not_available`
- Why: openHiTLS has no T61STRING ASN1_ITEM accessor.

## 3. `ASN1_T61STRING_new`
- Verdict: keep `not_available`
- Why: openHiTLS has no T61STRING object constructor.

## 4. `ASN1_TBOOLEAN_it`
- Verdict: keep `not_available`
- Why: openHiTLS exposes BOOLEAN only as a primitive tag decoded into bool, not as an ASN1_ITEM accessor.

## 5. `ASN1_TIME_adj`
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can compose UTC conversion, day/second adjustment, and ASN.1 time encoding through public `BSL_TIME` and template APIs, but does not expose an `ASN1_TIME *` object API.

## 6. `ASN1_TIME_check`
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can decode a public ASN.1 time buffer into `BSL_TIME` and validate it with `BSL_DateTimeCheck`, but does not expose an `ASN1_TIME *` object API.

## 7. `ASN1_TIME_cmp_time_t`
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can decode ASN.1 time buffers into `BSL_TIME`, convert UTC time to `BSL_TIME`, and compare them through public SAL time helpers.

## 8. `ASN1_TIME_compare`
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can decode two ASN.1 time buffers into `BSL_TIME` and compare them through public SAL time helpers.

## Batch 092 summary

Change to `partial`:
- `ASN1_TIME_adj`
- `ASN1_TIME_check`
- `ASN1_TIME_cmp_time_t`
- `ASN1_TIME_compare`

Keep `not_available`:
- `ASN1_T61STRING_free`
- `ASN1_T61STRING_it`
- `ASN1_T61STRING_new`
- `ASN1_TBOOLEAN_it`
