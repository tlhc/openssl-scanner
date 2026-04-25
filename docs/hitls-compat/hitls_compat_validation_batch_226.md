# openHiTLS Compatibility Validation Batch 226

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `NETSCAPE_*` legacy wrapper family lacking `analysis_doc`:
  - `i2d_NETSCAPE_CERT_SEQUENCE`
  - `i2d_NETSCAPE_SPKAC`
  - `i2d_NETSCAPE_SPKI`

Status:
- completed

Initial evidence:
- OpenSSL exposes public standalone wrapper encoders for:
  - `NETSCAPE_SPKI`
  - `NETSCAPE_SPKAC`
  - `NETSCAPE_CERT_SEQUENCE`
- OpenSSL also uses the `NETSCAPE_SPKI` encoder directly in the SPKI helper implementation.
- openHiTLS public installed tree does not expose any matching `NETSCAPE_*` object family or encode API.
- The only nearby public/open hit in openHiTLS is the `BSL_CID_NETSCAPE` object identifier constant, which is only an OID trace.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 3`

Reasoning boundary:
- All 3 interfaces remain `not_available`.
- OpenSSL side is a standalone legacy Netscape wrapper-object encode family.
- openHiTLS public installed headers do not provide:
  - `NETSCAPE_SPKI`
  - `NETSCAPE_SPKAC`
  - `NETSCAPE_CERT_SEQUENCE`
  object models or encode helpers.
- OID presence alone does not create a practical replacement path.

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L621)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L622)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L623)
- OpenSSL implementation evidence:
  - [x509spki.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509spki.c#L60)
  - [x509spki.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x509spki.c#L71)
- openHiTLS adjacent-only evidence:
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L509)

Batch 226 inventory:
- total interfaces: `3`
- `not_available = 3`
