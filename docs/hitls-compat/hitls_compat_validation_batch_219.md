# openHiTLS Compatibility Validation Batch 219

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `i2d_OCSP_*` family lacking `analysis_doc`:
  - `i2d_OCSP_BASICRESP`
  - `i2d_OCSP_CERTID`
  - `i2d_OCSP_CERTSTATUS`
  - `i2d_OCSP_CRLID`
  - `i2d_OCSP_ONEREQ`
  - `i2d_OCSP_REQINFO`
  - `i2d_OCSP_REQUEST`
  - `i2d_OCSP_RESPBYTES`
  - `i2d_OCSP_RESPDATA`
  - `i2d_OCSP_RESPID`
  - `i2d_OCSP_RESPONSE`
  - `i2d_OCSP_REVOKEDINFO`
  - `i2d_OCSP_SERVICELOC`
  - `i2d_OCSP_SIGNATURE`
  - `i2d_OCSP_SINGLERESP`

Status:
- completed

Initial evidence:
- OpenSSL exposes a complete OCSP ASN.1 object family in public headers:
  - `DECLARE_ASN1_FUNCTIONS(OCSP_SINGLERESP)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_CERTSTATUS)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_REVOKEDINFO)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_BASICRESP)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_RESPDATA)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_RESPID)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_RESPONSE)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_RESPBYTES)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_ONEREQ)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_CERTID)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_REQUEST)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_SIGNATURE)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_REQINFO)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_CRLID)`
  - `DECLARE_ASN1_FUNCTIONS(OCSP_SERVICELOC)`
- openHiTLS public installed tree does not expose an OCSP object family or OCSP encode API.
- The only public/open hits in openHiTLS are adjacent artifacts:
  - verification purpose constant for OCSP signing
  - OCSP-related OIDs in `bsl_obj.h`
- Those do not create a practical public replacement path for standalone OCSP wrapper-object encoders.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 15`

Reasoning boundary:
- All 15 interfaces stay `not_available`.
- The OpenSSL side is a standalone OCSP wrapper-object ASN.1 encode family.
- openHiTLS public installed headers do not provide:
  - `OCSP_REQUEST` / `OCSP_RESPONSE` object creation
  - OCSP response/basic-response/signature object model
  - OCSP request/response encoding helpers
- OID constants and verification-purpose references are adjacent capability signals only.
- They are insufficient for practical replaceability.

Representative evidence:
- OpenSSL declarations:
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L147)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L149)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L167)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L169)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L361)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L362)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L363)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L364)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L365)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L366)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L367)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L368)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L369)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L370)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L371)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L372)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L373)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L374)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L375)
- OpenSSL implementation evidence:
  - [ocsp_cl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_cl.c#L35)
  - [ocsp_srv.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_srv.c#L67)
  - [ocsp_ext.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_ext.c#L353)
- openHiTLS adjacent-only evidence:
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L311)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L182)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L201)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L246)

Batch 219 inventory:
- total interfaces: `15`
- `not_available = 15`
