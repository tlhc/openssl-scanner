# openHiTLS Compatibility Validation Batch 239

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)
- OpenSSL docs:
  - https://docs.openssl.org/3.5/man3/X509_check_purpose/
  - https://docs.openssl.org/3.0/man3/X509_LOOKUP_meth_new/

Scope:
- remaining X509 registry / policy / trust / object family lacking `analysis_doc`:
  - `X509_OBJECT_*`
  - `X509_PURPOSE_*`
  - `X509_TRUST_*`
  - `X509_policy_*`
  - `X509_SIG_*`
  - `X509_issuer_*`
  - `X509_load_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes several standalone X509 registry/helper surfaces here:
  - trust registry:
    - `X509_TRUST_*`
  - purpose registry:
    - `X509_PURPOSE_*`
  - lookup/store object wrapper:
    - `X509_OBJECT_*`
    - `X509_load_*`
  - policy-tree object family:
    - `X509_policy_*`
  - standalone signature wrapper helpers:
    - `X509_SIG_*`
  - issuer/hash convenience helpers:
    - `X509_issuer_*`
- openHiTLS public installed tree exposes adjacent but narrower public surfaces:
  - verification store context:
    - `HITLS_X509_StoreCtxNew`
    - `HITLS_X509_StoreCtxDup`
    - `HITLS_X509_ProviderStoreCtxNew`
    - `HITLS_X509_StoreCtxFree`
    - `HITLS_X509_StoreCtxCtrl`
    - `HITLS_X509_CertVerify`
    - `HITLS_X509_CertChainBuild`
  - verification purpose enum:
    - `HITLS_X509_VFY_PURPOSE_*`
    - `HITLS_X509_STORECTX_SET_PURPOSE`
  - direct parse-file helpers:
    - `HITLS_X509_CertParseFile`
    - `HITLS_X509_ProviderCertParseFile`
    - `HITLS_X509_CrlParseBundleFile`
- openHiTLS public installed tree does not expose:
  - an `X509_OBJECT` wrapper family
  - a purpose/trust registry object model
  - a policy-tree object family
  - `X509_LOOKUP`-style load-into-store helpers
  - a standalone `X509_SIG` wrapper family

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 60`

Reasoning boundary:
- All `60` interfaces remain `not_available`.
- The closest openHiTLS public analogue is `HITLS_X509_StoreCtx`, which supports verification configuration and purpose selection.
- That public surface does not create a practical replacement path for:
  - `X509_OBJECT_*` lookup/store wrapper operations
  - `X509_PURPOSE_*` registry enumeration and registration APIs
  - `X509_TRUST_*` registry enumeration and registration APIs
  - `X509_policy_*` policy-tree introspection APIs
  - `X509_load_*` file loading into `X509_LOOKUP`
  - `X509_SIG_*` standalone ASN.1 wrapper-object helpers
  - `X509_issuer_*` convenience compare/hash helpers
- `CertParseFile`/`CrlParseBundleFile` only parse files into objects or lists; they do not implement the OpenSSL `X509_LOOKUP` contract or object registry.
- `HITLS_X509_VFY_PURPOSE_*` only sets verification intent on `StoreCtx`; it does not implement the OpenSSL purpose/trust registry families.

Representative evidence:
- OpenSSL declarations:
  - [x509_vfy.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_vfy.h.in#L126)
  - [x509_vfy.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_vfy.h.in#L410)
  - [x509_vfy.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_vfy.h.in#L639)
  - [x509_vfy.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509_vfy.h.in#L824)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L552)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L586)
- OpenSSL implementation evidence:
  - [v3_purp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_purp.c#L106)
  - [x509_trust.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_trust.c#L83)
  - [x509_lu.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_lu.c#L635)
  - [x509_lu.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_lu.c#L725)
  - [by_file.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/by_file.c#L92)
  - [pcy_tree.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/pcy_tree.c#L628)
  - [pcy_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/pcy_lib.c#L20)
  - [x509_set.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_set.c#L182)
- openHiTLS public adjacent surfaces:
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L49)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L58)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L69)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L78)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L88)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L118)
  - [hitls_pki_x509.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_x509.h#L129)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L306)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L326)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L150)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L210)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L230)
  - [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L133)
- openHiTLS implementation boundary:
  - [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L211)
  - [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L751)
  - [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L843)
  - [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L1801)
  - [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L1955)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1213)

Batch 239 inventory:
- total interfaces: `60`
- `not_available = 60`
