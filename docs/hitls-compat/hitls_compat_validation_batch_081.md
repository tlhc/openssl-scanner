# openHiTLS Compatibility Validation Batch 081

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `ASN1_ENUMERATED_new`
- `ASN1_ENUMERATED_set`
- `ASN1_ENUMERATED_set_int64`
- `ASN1_ENUMERATED_to_BN`
- `ASN1_FBOOLEAN_it`
- `ASN1_GENERALIZEDTIME_adj`
- `ASN1_GENERALIZEDTIME_check`
- `ASN1_GENERALIZEDTIME_dup`

Status:
- completed

Initial evidence:
- openHiTLS public ASN.1 support continues to expose primitive tags plus buffer/template encode/decode, not object-style `ASN1_*` helpers.
- Two relevant public building blocks appear here:
  - `BSL_ASN1_DecodePrimitiveItem(BSL_ASN1_TAG_ENUMERATED -> int)`
  - `BSL_ASN1_DecodePrimitiveItem(BSL_ASN1_TAG_GENERALIZEDTIME -> BSL_TIME)`
- The threshold question is whether those building blocks are sufficient to claim a public analogue for a given OpenSSL helper.

## 1. `ASN1_ENUMERATED_new`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L613), [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L30)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1389)
- Verdict: keep `not_available`
- Why: openHiTLS can process caller-owned `ENUMERATED` buffers, but does not expose an `ASN1_ENUMERATED` object constructor.

## 2. `ASN1_ENUMERATED_set`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L715), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L584)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1389), [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L1325)
- Verdict: keep `not_available`
- Why: `BSL_ASN1_EncodeLimb` can encode caller-owned limbs under the `ENUMERATED` tag, but it is not an `ASN1_ENUMERATED` object setter.

## 3. `ASN1_ENUMERATED_set_int64`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L712), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L579)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1389)
- Verdict: keep `not_available`
- Why: openHiTLS has no int64-capable `ASN1_ENUMERATED` object setter; `EncodeLimb` is still caller-buffer based.

## 4. `ASN1_ENUMERATED_to_BN`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L718), [a_int.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_int.c#L612)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L44), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L174), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L173), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L392)
- Verdict: keep `not_available`
- Why: openHiTLS can decode `ENUMERATED` into an `int`, but it does not expose a public `ENUMERATED -> BN` object conversion.

## 5. `ASN1_FBOOLEAN_it`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L69)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L35), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L184), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L164), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L397)
- Verdict: keep `not_available`
- Why: openHiTLS exposes BOOLEAN only as a primitive tag decoded into `bool`, not as an OpenSSL-style `ASN1_ITEM` accessor.

## 6. `ASN1_GENERALIZEDTIME_adj`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L625), [a_gentm.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_gentm.c#L62)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L196), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1035), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L1077), [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L1301)
- Verdict: keep `not_available`
- Why: openHiTLS can encode caller-owned `BSL_TIME` values under the `GENERALIZEDTIME` tag, but it does not expose an `ASN1_GENERALIZEDTIME` object API or a `time_t + offset` adjustment helper.

## 7. `ASN1_GENERALIZEDTIME_check`
- OpenSSL declaration/implementation: [asn1.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1.h.in#L622), [a_gentm.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/a_gentm.c#L33)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L212), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L223), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L406)
- Verdict: change to `not_available` (revised 2026-04-25; see batch_269)
- Why: openHiTLS can validate and decode a public ASN.1 `GENERALIZEDTIME` buffer into `BSL_TIME` through `BSL_ASN1_DecodePrimitiveItem`, but it does not expose an `ASN1_GENERALIZEDTIME` object API.

## 8. `ASN1_GENERALIZEDTIME_dup`
- OpenSSL implementation: [tasn_typ.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/tasn_typ.c#L38)
- openHiTLS declaration/implementation: [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L57), [bsl_asn1.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_asn1.h#L186), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L223), [bsl_asn1.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/asn1/src/bsl_asn1.c#L406)
- Verdict: keep `not_available`
- Why: openHiTLS can decode `GENERALIZEDTIME` content into `BSL_TIME`, but it does not expose an `ASN1_GENERALIZEDTIME` object duplication API.

## Batch 081 summary

Change to `partial`:
- `ASN1_GENERALIZEDTIME_check`

Keep `not_available`:
- `ASN1_ENUMERATED_new`
- `ASN1_ENUMERATED_set`
- `ASN1_ENUMERATED_set_int64`
- `ASN1_ENUMERATED_to_BN`
- `ASN1_FBOOLEAN_it`
- `ASN1_GENERALIZEDTIME_adj`
- `ASN1_GENERALIZEDTIME_dup`

Main observation:
- This batch reinforces the same rule as Batch 080: primitive decode/encode support can justify a narrow `partial`, but generic building blocks do not automatically upgrade object-style APIs.
