# openHiTLS Compatibility Validation Batch 126

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `X509_ALGORS_it`
- `X509_ALGOR_cmp`
- `X509_ALGOR_copy`
- `X509_ALGOR_dup`
- `X509_ALGOR_free`
- `X509_ALGOR_get0`
- `X509_ALGOR_it`
- `X509_ALGOR_new`
- `X509_ALGOR_set0`
- `X509_ALGOR_set_md`

Status:
- completed

Initial evidence:
- OpenSSL declares the public `X509_ALGOR` helper family in [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L463), [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L470), and [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L500).
- OpenSSL implements the object and helper surface in [x_algor.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/x_algor.c#L18), [x_algor.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/x_algor.c#L27), [x_algor.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/x_algor.c#L31), [x_algor.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/x_algor.c#L56), [x_algor.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/x_algor.c#L74), and [x_algor.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/asn1/x_algor.c#L87).
- openHiTLS has an internal ASN.1 algorithm identifier representation in [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L125) and internal parse/encode helpers in [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L159) and [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L173), but these are not public headers.
- openHiTLS public PKI types only expose signing-parameter metadata in [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L212), not an `X509_ALGOR`-style heap object/helper family.
- openHiTLS CMS code also has an internal `CMS_AlgId` plus `AlgorithmIdentifier` template path in [hitls_cms_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/include/hitls_cms_local.h#L51) and [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L75), but again not public API.

Verdict:
- keep `not_available` for all entries in scope.
