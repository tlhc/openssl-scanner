# openHiTLS Compatibility Validation Batch 002

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)

Scope:
- `X509_new`
- `X509_free`
- `X509_dup`
- `PEM_read_bio_X509`
- `X509_REQ_new`
- `X509_REQ_free`
- `X509_get_subject_name`
- `X509_get_issuer_name`
- `X509_get_ext_d2i`
- `X509_verify_cert`
- `X509_STORE_add_cert`
- `X509_STORE_free`
- `X509_STORE_CTX_get_error`
- `OCSP_BASICRESP_free`
- `OCSP_RESPONSE_free`

Rule reminder:
- `available`: near-direct public replacement with thin adaptation only.
- `partial`: public openHiTLS API can realize the function, but signature, object model, or lifecycle differs materially.
- `not_available`: no direct public openHiTLS API for the OpenSSL symbol.
- Functional equivalence takes precedence over style equivalence, but direct-public-API absence still prevents `available`.

## 1. `X509_new`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CertNew()`

Verified evidence:
- OpenSSL declaration: `/opt/homebrew/include/openssl/x509.h` (constructor family; public X509 object API)
- openHiTLS declaration: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L34)
- openHiTLS implementation: `pki/x509_cert/src/...` (allocation path), plus CSR/cert usage throughout test cases

Assessment:
- Direction is correct.
- Both APIs create an empty certificate object, but object type and downstream control API differ.

Verdict:
- Change to `available`

## 2. `X509_free`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CertFree(cert)`

Verified evidence:
- openHiTLS declaration: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L53)
- usage/ownership evidence: [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L377), [hitls_cms_util.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_util.c#L76)

Assessment:
- Functional free exists.
- Refcount and ownership model are similar enough, but the concrete object model differs from OpenSSL.

Verdict:
- Change to `available`

## 3. `X509_dup`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CertDup(cert)`

Verified evidence:
- openHiTLS declaration: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L63)

Assessment:
- Public duplicate API exists.
- Semantics are close, but object type and internal duplication strategy differ.

Verdict:
- Change to `available`

## 4. `PEM_read_bio_X509`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &encode, &cert)`

Verified evidence:
- openHiTLS declaration: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L128)

Assessment:
- Public PEM parse path exists.
- OpenSSL reads from BIO directly; openHiTLS parses from buffer with explicit format.

Verdict:
- Keep `partial`

## 5. `X509_REQ_new`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CsrNew()`

Verified evidence:
- OpenSSL declaration family: `openssl-3.0.9/include/openssl/x509.h:747-748`, `openssl-3.0.9/include/openssl/asn1.h:324-326`
- openHiTLS declaration: [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L34)

Verdict:
- Change to `available`

## 6. `X509_REQ_free`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CsrFree(csr)`

Verified evidence:
- OpenSSL declaration family: `openssl-3.0.9/include/openssl/x509.h:747-748`, `openssl-3.0.9/include/openssl/asn1.h:324-326`
- openHiTLS declaration: [hitls_pki_csr.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_csr.h#L54)

Verdict:
- Change to `available`

## 7. `X509_get_subject_name`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_SUBJECT_DN, ...)`

Verified evidence:
- openHiTLS generic accessor declaration: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108)
- usage examples: [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L1025)

Assessment:
- Subject DN is obtainable, but via generic ctrl dispatch and different returned data model.

Verdict:
- Keep `partial`

## 8. `X509_get_issuer_name`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ISSUER_DN, ...)`

Verified evidence:
- generic accessor declaration: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108)
- usage examples: [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L1025), [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L1048)

Verdict:
- Keep `partial`

## 9. `X509_get_ext_d2i`

Current JSON:
- `status = not_available`

Verified evidence:
- No direct public `X509_get_ext_d2i` style API found in public headers.
- Some extension access exists through specialized ctrl commands, but not as a general typed decode API.

Verdict:
- Keep `not_available`

## 10. `X509_verify_cert`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_CertVerify(storeCtx, chain)`

Verified evidence:
- openHiTLS declaration: [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L129)
- implementation entry: [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L1743)
- usage example: [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L1985)

Assessment:
- Functional verification API exists.
- openHiTLS requires explicit chain argument and store context preparation that differ from OpenSSL's single-argument API.

Verdict:
- Keep `partial`

## 11. `X509_STORE_add_cert`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA, cert, ...)`

Verified evidence:
- store ctrl declaration: [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L118)
- usage example: [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L1967)

Assessment:
- Functionality is reachable through generic store ctrl dispatch, not dedicated add-cert API.

Verdict:
- Keep `partial`

## 12. `X509_STORE_free`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_StoreCtxFree(storeCtx)`

Verified evidence:
- declaration: [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L78)
- implementation: [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L127)

Verdict:
- Keep `partial`

## 13. `X509_STORE_CTX_get_error`

Current JSON:
- `status = partial`
- `hitls = HITLS_X509_StoreCtxCtrl(STORECTX_GET_ERROR)`

Verified evidence:
- store ctrl declaration: [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L118)
- implementation entry: [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L843)

Verdict:
- Keep `partial`

## 14. `OCSP_BASICRESP_free`

Current JSON:
- `status = not_available`

Verified evidence:
- No public OCSP response object/free API found in [`openhitls-upstream/include/pki`](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki).

Verdict:
- Keep `not_available`

## 15. `OCSP_RESPONSE_free`

Current JSON:
- `status = not_available`

Verified evidence:
- No public OCSP response object/free API found in [`openhitls-upstream/include/pki`](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki).

Verdict:
- Keep `not_available`

## Batch 002 summary

Change current status verdicts:
- `X509_new`: `partial` -> `available`
- `X509_free`: `partial` -> `available`
- `X509_dup`: `partial` -> `available`
- `X509_REQ_new`: `partial` -> `available`
- `X509_REQ_free`: `partial` -> `available`

Keep current status verdicts:
- `PEM_read_bio_X509`
- `X509_get_subject_name`
- `X509_get_issuer_name`
- `X509_verify_cert`
- `X509_STORE_add_cert`
- `X509_STORE_free`
- `X509_STORE_CTX_get_error`

Keep current `not_available` verdicts:
- `X509_get_ext_d2i`
- `OCSP_BASICRESP_free`
- `OCSP_RESPONSE_free`

Main observation:
- Batch 002 confirms the object lifecycle APIs are stronger than the previous baseline suggested.
- The main remaining uncertainty in this family sits in generic ctrl-based accessors and store/verification orchestration, not constructors/destructors.
