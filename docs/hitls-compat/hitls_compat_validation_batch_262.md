# openHiTLS Compatibility Validation Batch 262

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl-3.0.9)

Scope:
- report-side unknown `sk_*` and `lh_*` template-generated container helpers

Status:
- completed

Initial evidence:
- OpenSSL safe-stack macros generate type-specific `sk_TYPE_*` wrappers over the generic `OPENSSL_sk_*` stack container in [safestack.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/safestack.h.in#L67) and document them as a stack-container family in [DEFINE_STACK_OF.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/DEFINE_STACK_OF.pod#L68).
- OpenSSL lhash macros generate type-specific `lh_TYPE_*` wrappers over the generic `OPENSSL_LH_*` dynamic hash-table family in [OPENSSL_LH_COMPFUNC.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/OPENSSL_LH_COMPFUNC.pod#L57).
- openHiTLS public installed surface exposes a generic linked-list family in [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L49):
  - element count via [BSL_LIST_COUNT](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L123)
  - indexed access via [BSL_LIST_GetIndexNode](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L255)
  - copy via [BSL_LIST_Copy](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L268)
  - sort via [BSL_LIST_Sort](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L283)
  - allocation via [BSL_LIST_New](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L295)
- openHiTLS also exposes a small set of typed aliases over `BslList`:
  - [HITLS_X509_List](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L32)
  - [HITLS_CIPHER_List](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_crypt_type.h#L62)
  - [HITLS_TrustedCAList](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_type.h#L67)
  - [HITLS_CERT_Chain](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_type.h#L73)
  - [HITLS_CERT_CRLList](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_type.h#L79)

Verdict:
- keep `available = 0`
- keep `partial = 0`
- set `not_available = 424`

Reasoning boundary:
- `sk_*` helpers stay `not_available` because OpenSSL exposes a generated `STACK_OF(TYPE)` object model with:
  - arbitrary OpenSSL element types
  - stack-specific reserve/insert/delete_ptr/find_all/deep_copy/set_cmp_func semantics
  - typed function names tied to the original OpenSSL type family
- openHiTLS public surface gives developers a generic `BslList` plus a few subsystem-owned aliases. That surface is useful as an internal adjacent container, but it does not provide a safe-stack-compatible wrapper family for the reported `sk_*` interface names.
- `lh_*` helpers stay `not_available` because OpenSSL exposes a generated typed hash-table family with:
  - caller-provided hash and compare callbacks
  - retrieve/insert/delete/doall/down-load/error operations
  - `LHASH_OF(TYPE)` object model
- openHiTLS public installed headers in this scope expose linked-list helpers and selected list aliases. The public boundary stops before a typed hash-table family.

Representative evidence:
- OpenSSL declarations and docs:
  - [safestack.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/safestack.h.in#L67)
  - [DEFINE_STACK_OF.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/DEFINE_STACK_OF.pod#L68)
  - [OPENSSL_LH_COMPFUNC.pod](https://github.com/openssl/openssl/blob/openssl-3.0.9/doc/man3/OPENSSL_LH_COMPFUNC.pod#L57)
- openHiTLS public declarations:
  - [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L49)
  - [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L123)
  - [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L255)
  - [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L268)
  - [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L283)
  - [bsl_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_list.h#L295)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L32)
  - [hitls_crypt_type.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_crypt_type.h#L62)
  - [hitls_cert_type.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_type.h#L67)
  - [hitls_cert_type.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_type.h#L73)
  - [hitls_cert_type.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_cert_type.h#L79)

Batch 262 inventory:
- total interfaces: `424`
- `available = 0`
- `partial = 0`
- `not_available = 424`
