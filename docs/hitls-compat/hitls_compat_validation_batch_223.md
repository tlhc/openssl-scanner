# openHiTLS Compatibility Validation Batch 223

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `ext/value typed wrappers` lacking `analysis_doc`:
  - `i2d_ACCESS_DESCRIPTION`
  - `i2d_ADMISSIONS`
  - `i2d_ADMISSION_SYNTAX`
  - `i2d_AUTHORITY_INFO_ACCESS`
  - `i2d_AUTHORITY_KEYID`
  - `i2d_BASIC_CONSTRAINTS`
  - `i2d_CERTIFICATEPOLICIES`
  - `i2d_DIRECTORYSTRING`
  - `i2d_DISPLAYTEXT`
  - `i2d_DIST_POINT`
  - `i2d_DIST_POINT_NAME`
  - `i2d_EDIPARTYNAME`
  - `i2d_EXTENDED_KEY_USAGE`
  - `i2d_ISSUING_DIST_POINT`
  - `i2d_NAMING_AUTHORITY`
  - `i2d_NOTICEREF`
  - `i2d_OTHERNAME`
  - `i2d_PKEY_USAGE_PERIOD`
  - `i2d_POLICYINFO`
  - `i2d_POLICYQUALINFO`
  - `i2d_PROFESSION_INFO`
  - `i2d_PROXY_CERT_INFO_EXTENSION`
  - `i2d_PROXY_POLICY`
  - `i2d_USERNOTICE`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone encode wrappers for these X.509 extension/value objects.
- openHiTLS public installed PKI surface exposes extension control on owning objects:
  - `HITLS_X509_ExtCtrl`
  - typed ext get/set commands in `hitls_pki_types.h`
- openHiTLS also has internal extension encoding/parsing helpers in `pki/x509_common/src/hitls_x509_ext.c`.
- Those helpers operate behind certificate / CRL / CSR owning objects and internal data structures.
- openHiTLS public installed headers do not expose standalone wrapper encode entrypoints for these values.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 24`

Reasoning boundary:
- All 24 interfaces remain `not_available`.
- openHiTLS can read/write many of these extensions when attached to cert/crl/csr objects.
- That capability does not provide a public standalone encoder for wrapper objects like:
  - `ACCESS_DESCRIPTION`
  - `AUTHORITY_KEYID`
  - `DIST_POINT`
  - `POLICYINFO`
  - `USERNOTICE`
- Practical replaceability fails at the public object-model boundary.

Representative evidence:
- OpenSSL declarations:
  - [x509v3.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h)
- OpenSSL encode use sites:
  - [v3_conf.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/v3_conf.c#L289)
  - [x509_acert.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509_acert.c#L291)
- openHiTLS public declarations:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L99)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L66)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L92)
- openHiTLS implementation evidence:
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L187)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L425)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L538)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L765)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L981)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1368)

Batch 223 inventory:
- total interfaces: `24`
- `not_available = 24`
