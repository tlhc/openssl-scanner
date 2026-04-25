# openHiTLS Compatibility Validation Batch 034

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `X509_verify_cert_error_string`
- `X509_NAME_oneline`
- `X509_verify`
- `X509_EXTENSION_get_data`
- `X509_NAME_ENTRY_get_data`
- `X509_NAME_get_entry`
- `X509_NAME_add_entry_by_txt`
- `X509_NAME_get_text_by_NID`

Status:
- completed

Initial evidence:
- This family is the next coherent X509-heavy cluster without `analysis_doc`.
- Current scan aggregation shows:
  - `X509_verify_cert_error_string`: 15 repos
  - `X509_NAME_oneline`: 11 repos
  - `X509_verify`: 11 repos
  - `X509_EXTENSION_get_data`: 9 repos
  - `X509_NAME_ENTRY_get_data`: 9 repos
  - `X509_NAME_get_entry`: 9 repos
  - `X509_NAME_add_entry_by_txt`: 8 repos
  - `X509_NAME_get_text_by_NID`: 8 repos
- The main distinction in this batch is between:
  - public capability that still exists but through a different object/workflow
  - internal-only or certificate-bound helpers that do not replace the generic OpenSSL getter APIs

## 1. `X509_verify_cert_error_string`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L315), [x509_txt.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_txt.c#L21)
- openHiTLS public/internal evidence: [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L118), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L369), [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L503)
- Verdict: keep `not_available`
- Why: openHiTLS exposes numeric verification errors through store-context APIs, but no public error-code-to-string helper.

## 2. `X509_NAME_oneline`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L605), [x509_obj.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_obj.c#L25)
- openHiTLS public/internal evidence: [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L45), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L391), [hitls_pki_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/print/src/hitls_pki_print.c#L1138), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L296)
- Verdict: keep `partial`
- Why: openHiTLS can print a DN list through `HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_DNNAME, ...)`, but only via `BSL_UIO` output plumbing and DN-list objects, not a direct `char *` helper on `X509_NAME`.

## 3. `X509_verify`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L317), [x_all.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x_all.c#L31)
- openHiTLS declaration/implementation: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L95), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L382), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1100), [eal_pkey_sign.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_sign.c#L78)
- Verdict: keep `partial`
- Why: openHiTLS can realize the same certificate-signature verification through `HITLS_X509_CertDigest + CRYPT_EAL_PkeyVerify`, but not as a single-call API.

## 4. `X509_EXTENSION_get_data`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L934), [x509_v3.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509_v3.c#L223)
- openHiTLS declaration/implementation: [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L66), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L239), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1303), [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1368)
- Verdict: keep `partial`
- Why: openHiTLS can fetch DER-encoded extension value via `HITLS_X509_ExtCtrl(..., HITLS_X509_EXT_GET_GENERIC, ...)`, but requires a generic-get structure with OID input and allocated output, not a direct `ASN1_OCTET_STRING *` view.

## 5. `X509_NAME_ENTRY_get_data`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L869), [x509name.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509name.c#L349)
- openHiTLS public/internal evidence: [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L110), [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L461), [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L60)
- Verdict: change to `not_available`
- Why: openHiTLS does not expose a public `NameEntry` type or dedicated getter for the entry value. The underlying `HITLS_X509_NameNode` type is local-only.

## 6. `X509_NAME_get_entry`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L840), [x509name.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509name.c#L92)
- openHiTLS public/internal evidence: [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L110), [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L461), [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L60)
- Verdict: change to `not_available`
- Why: there is no public equivalent that returns a DN entry object. DN entries are stored as local-only `HITLS_X509_NameNode` items inside a generic list.

## 7. `X509_NAME_add_entry_by_txt`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L858), [x509name.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509name.c#L170)
- openHiTLS declaration/implementation: [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L110), [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L131), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L151), [hitls_x509_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ctrl.c#L414)
- Verdict: keep `partial`
- Why: openHiTLS can build DN lists from public `HITLS_X509_DN` structures through `HITLS_X509_AddDnName`, but this is not a direct mutator on an OpenSSL `X509_NAME` object.

## 8. `X509_NAME_get_text_by_NID`
- OpenSSL declaration/implementation: [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L828), [x509name.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x509name.c#L19)
- openHiTLS public/internal evidence: [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L108), [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L56), [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L636), [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L60)
- Verdict: change to `not_available`
- Why: openHiTLS has cert-specific string getters such as `GET_SUBJECT_DN_STR` and `GET_ISSUER_DN_STR`, but no public generic “get DN entry text by NID” helper on a DN object.

## Batch 034 summary

Keep `not_available`:
- `X509_verify_cert_error_string`

Change to `not_available`:
- `X509_NAME_ENTRY_get_data`
- `X509_NAME_get_entry`
- `X509_NAME_get_text_by_NID`

Keep `partial`:
- `X509_NAME_oneline`
- `X509_verify`
- `X509_EXTENSION_get_data`
- `X509_NAME_add_entry_by_txt`

Main observation:
- This batch is where the public-API boundary matters most.
- openHiTLS has DN and extension internals, but several OpenSSL getter-style name APIs do not have public object-level equivalents and should not be overstated as compatible.
