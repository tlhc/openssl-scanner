# openHiTLS Compatibility Validation Batch 127

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `X509_ATTRIBUTE_count`
- `X509_ATTRIBUTE_create`
- `X509_ATTRIBUTE_create_by_NID`
- `X509_ATTRIBUTE_create_by_OBJ`
- `X509_ATTRIBUTE_create_by_txt`
- `X509_ATTRIBUTE_dup`
- `X509_ATTRIBUTE_free`
- `X509_ATTRIBUTE_get0_data`
- `X509_ATTRIBUTE_get0_object`
- `X509_ATTRIBUTE_get0_type`
- `X509_ATTRIBUTE_it`
- `X509_ATTRIBUTE_new`
- `X509_ATTRIBUTE_set1_data`
- `X509_ATTRIBUTE_set1_object`

Status:
- completed

Initial evidence:
- OpenSSL declares the public `X509_ATTRIBUTE` helper family in [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L464), [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L539), [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L540), and [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L962).
- OpenSSL implements the object and helper surface in [x_attrib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x_attrib.c#L28), [x_attrib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x_attrib.c#L33), and [x_attrib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/x509/x_attrib.c#L36).
- openHiTLS has internal attribute-list parse/encode helpers in [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L239), [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L250), [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L252), and [hitls_x509_local.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/include/hitls_x509_local.h#L256), but these are internal-only local headers.
- openHiTLS CMS parsing uses those internal attribute-list helpers in [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L440), [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L455), and [hitls_cms_signdata.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/cms/src/hitls_cms_signdata.c#L830), but public CMS headers do not expose generic attribute object constructors/getters.
- No public openHiTLS header exposes an `X509_ATTRIBUTE`-style heap object/helper family.

Verdict:
- keep `not_available` for all entries in scope.
