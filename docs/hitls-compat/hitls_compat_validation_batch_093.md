# openHiTLS Compatibility Validation Batch 093

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_TIME_diff`
- `ASN1_TIME_dup`
- `ASN1_TIME_free`
- `ASN1_TIME_it`
- `ASN1_TIME_new`
- `ASN1_TIME_normalize`
- `ASN1_TIME_print_ex`
- `ASN1_TIME_set`

Status:
- completed

Initial evidence:
- openHiTLS public time support already established in earlier batches:
  - decode ASN.1 time into `BSL_TIME`
  - compare via `BSL_SAL_DateTimeCompare`
  - print via `BSL_PRINT_Time`
  - encode caller-owned `BSL_TIME` back through `BSL_ASN1_EncodeTemplate`
- That supports a few narrow composed analogues, but still not the OpenSSL `ASN1_TIME *` object family.

## 1. `ASN1_TIME_diff`
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can decode ASN.1 time buffers into `BSL_TIME` and compute a public second-level difference through `BSL_SAL_DateTimeCompare`, but it does not expose an `ASN1_TIME` object API.

## 2. `ASN1_TIME_dup`
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_TIME` object duplication API.

## 3. `ASN1_TIME_free`
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_TIME` object lifecycle API.

## 4. `ASN1_TIME_it`
- Verdict: keep `not_available`
- Why: openHiTLS exposes ASN.1 time handling only as primitive tags in buffer/template APIs, not as an `ASN1_ITEM` accessor.

## 5. `ASN1_TIME_new`
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_TIME` object constructor.

## 6. `ASN1_TIME_normalize`
- Verdict: keep `not_available`
- Why: openHiTLS exposes `BSL_TIME` validation and encode/decode utilities, but not an `ASN1_TIME` object normalization helper.

## 7. `ASN1_TIME_print_ex`
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can decode a public ASN.1 time buffer into `BSL_TIME` and print it through `BSL_PRINT_Time`, but it does not expose an `ASN1_TIME` object API or BIO-based helper.

## 8. `ASN1_TIME_set`
- Verdict: change to `partial`
- Why: openHiTLS can convert UTC time into `BSL_TIME` and encode it as ASN.1 time through public template APIs, but it does not expose an `ASN1_TIME` object API.

## Batch 093 summary

Change to `partial`:
- `ASN1_TIME_diff`
- `ASN1_TIME_print_ex`
- `ASN1_TIME_set`

Keep `not_available`:
- `ASN1_TIME_dup`
- `ASN1_TIME_free`
- `ASN1_TIME_it`
- `ASN1_TIME_new`
- `ASN1_TIME_normalize`
