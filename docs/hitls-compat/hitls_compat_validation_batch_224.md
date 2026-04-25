# openHiTLS Compatibility Validation Batch 224

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `RFC3779 AS/IP range wrappers` lacking `analysis_doc`:
  - `i2d_ASIdOrRange`
  - `i2d_ASIdentifierChoice`
  - `i2d_ASIdentifiers`
  - `i2d_ASRange`
  - `i2d_IPAddressChoice`
  - `i2d_IPAddressFamily`
  - `i2d_IPAddressOrRange`
  - `i2d_IPAddressRange`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone ASN.1 object families for RFC3779 address/resource wrappers:
  - `DECLARE_ASN1_FUNCTIONS(ASRange)`
  - `DECLARE_ASN1_FUNCTIONS(ASIdOrRange)`
  - `DECLARE_ASN1_FUNCTIONS(ASIdentifierChoice)`
  - `DECLARE_ASN1_FUNCTIONS(ASIdentifiers)`
  - `DECLARE_ASN1_FUNCTIONS(IPAddressRange)`
  - `DECLARE_ASN1_FUNCTIONS(IPAddressOrRange)`
  - `DECLARE_ASN1_FUNCTIONS(IPAddressChoice)`
  - `DECLARE_ASN1_FUNCTIONS(IPAddressFamily)`
- openHiTLS public installed PKI surface does not expose a corresponding RFC3779 object family or encode API.
- The nearby openHiTLS public extension surface covers generic extension operations and general names, but there are no public hits for these exact RFC3779 wrapper types.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 8`

Reasoning boundary:
- All 8 interfaces remain `not_available`.
- OpenSSL side is a standalone wrapper-object encode family.
- openHiTLS public installed headers do not provide:
  - `AS*` resource wrapper objects
  - `IPAddress*` resource wrapper objects
  - public encode helpers for RFC3779 range/address structures
- Generic extension or general-name support does not create a practical standalone replacement path for these wrappers.

Representative evidence:
- OpenSSL declarations:
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L876)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L877)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L878)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L879)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L928)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L929)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L930)
  - [x509v3.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509v3.h.in#L931)
- openHiTLS adjacent-only public evidence:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L104)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L66)
  - [hitls_pki_utils.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_utils.h#L100)
- openHiTLS internal general-name helpers, showing the nearby but different boundary:
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L246)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L369)
  - [hitls_x509_ext.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_common/src/hitls_x509_ext.c#L1214)

Batch 224 inventory:
- total interfaces: `8`
- `not_available = 8`
