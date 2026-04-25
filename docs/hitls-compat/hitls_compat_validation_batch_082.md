# openHiTLS Compatibility Validation Batch 082

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_GENERALIZEDTIME_free`
- `ASN1_GENERALIZEDTIME_it`
- `ASN1_GENERALIZEDTIME_new`
- `ASN1_GENERALIZEDTIME_print`
- `ASN1_GENERALIZEDTIME_set`
- `ASN1_GENERALIZEDTIME_set_string`
- `ASN1_GENERALSTRING_free`
- `ASN1_GENERALSTRING_it`

Status:
- completed

Initial evidence:
- openHiTLS public ASN.1 support for `GENERALIZEDTIME` is still buffer-oriented:
  - decode: `BSL_ASN1_DecodePrimitiveItem(... -> BSL_TIME)`
  - encode: caller-owned `BSL_TIME` under `BSL_ASN1_TAG_GENERALIZEDTIME` through `BSL_ASN1_EncodeTemplate`
  - print: `BSL_PRINT_Time`
- This is enough for narrow composed public analogues in `set` and `print`, but not enough for OpenSSL's object lifecycle / `ASN1_ITEM` APIs.

## 1. `ASN1_GENERALIZEDTIME_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L624), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L38)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L223), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1035)
- Verdict: keep `not_available`
- Why: openHiTLS can decode or encode `GENERALIZEDTIME` through `BSL_TIME` buffers, but it does not expose an `ASN1_GENERALIZEDTIME` object lifecycle API.

## 2. `ASN1_GENERALIZEDTIME_it`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L38)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186)
- Verdict: keep `not_available`
- Why: openHiTLS exposes `GENERALIZEDTIME` only as a primitive ASN.1 tag in buffer/template APIs, not as an `ASN1_ITEM` accessor.

## 3. `ASN1_GENERALIZEDTIME_new`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L38)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L223), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1035)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_GENERALIZEDTIME` object constructor.

## 4. `ASN1_GENERALIZEDTIME_print`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L807), [a_gentm.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_gentm.c#L81)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186), [bsl_print.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/print/include/bsl_print.h#L86), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L223), [bsl_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/print/src/bsl_print.c#L167)
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can decode a public `GENERALIZEDTIME` buffer into `BSL_TIME` and print it through `BSL_PRINT_Time`, but it does not expose an `ASN1_GENERALIZEDTIME` object API or BIO-based helper.

## 5. `ASN1_GENERALIZEDTIME_set`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L623), [a_gentm.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_gentm.c#L56)
- openHiTLS declaration/implementation: [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L690), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196), [sal_time.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/sal/src/sal_time.c#L376), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1035), [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L1301)
- Verdict: change to `partial`
- Why: openHiTLS can convert UTC time into `BSL_TIME` and encode it under the `GENERALIZEDTIME` tag, but it does not expose an `ASN1_GENERALIZEDTIME` object API.

## 6. `ASN1_GENERALIZEDTIME_set_string`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L628), [a_gentm.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_gentm.c#L38)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L223)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose a public string-to-`GENERALIZEDTIME` helper.

## 7. `ASN1_GENERALSTRING_free`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L664), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L36)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an `ASN1_GENERALSTRING` object lifecycle API.

## 8. `ASN1_GENERALSTRING_it`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L664), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L36)
- openHiTLS declaration: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196)
- Verdict: keep `not_available`
- Why: openHiTLS does not expose an OpenSSL-style `ASN1_GENERALSTRING` ASN1_ITEM accessor.

## Batch 082 summary

Change to `partial`:
- `ASN1_GENERALIZEDTIME_print`
- `ASN1_GENERALIZEDTIME_set`

Keep `not_available`:
- `ASN1_GENERALIZEDTIME_free`
- `ASN1_GENERALIZEDTIME_it`
- `ASN1_GENERALIZEDTIME_new`
- `ASN1_GENERALIZEDTIME_set_string`
- `ASN1_GENERALSTRING_free`
- `ASN1_GENERALSTRING_it`

Main observation:
- `GENERALIZEDTIME` is now the clearest example of a public composed analogue without object equivalence.
- openHiTLS can work with public time buffers and print/encode them, but it still does not expose OpenSSL-style `ASN1_GENERALIZEDTIME *` helpers.
