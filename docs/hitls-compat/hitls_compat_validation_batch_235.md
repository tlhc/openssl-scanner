# openHiTLS Compatibility Validation Batch 235

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `OCSP_*` family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a complete OCSP object and helper family in public headers and `crypto/ocsp`, including:
  - object constructors / destructors / ASN.1 items
  - request / response / basic-response helpers
  - extension accessors and mutators
  - signing / verification helpers
  - print / HTTP request helpers
- openHiTLS public installed tree does not expose an OCSP object family or OCSP helper surface.
- The only public/open traces in openHiTLS are adjacent OIDs and verification-purpose constants:
  - `BSL_CID_PKIX_OCSP_*`
  - `BSL_CID_AD_OCSP`
  - `BSL_CID_KP_OCSPSIGNING`
  - verify-purpose branch for OCSP signing

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 137`

Reasoning boundary:
- All `137` interfaces remain `not_available`.
- OpenSSL side here is a standalone OCSP object / helper subsystem.
- openHiTLS public installed headers do not provide:
  - `OCSP_REQUEST` / `OCSP_RESPONSE` / `OCSP_BASICRESP` object APIs
  - OCSP extension helpers
  - OCSP signing / verification / HTTP helpers
  - print / status helper surface
- OID presence and verify-purpose branches do not create a practical public replacement path.

Representative evidence:
- OpenSSL declarations:
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L208)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L223)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L229)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L254)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L286)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L289)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L300)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L312)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L361)
  - [ocsp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ocsp.h.in#L382)
- OpenSSL implementation evidence:
  - [ocsp_cl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_cl.c#L70)
  - [ocsp_cl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_cl.c#L106)
  - [ocsp_cl.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_cl.c#L273)
  - [ocsp_srv.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_srv.c#L165)
  - [ocsp_srv.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_srv.c#L213)
  - [ocsp_prn.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_prn.c#L89)
  - [ocsp_prn.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_prn.c#L134)
  - [ocsp_http.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_http.c#L15)
  - [ocsp_ext.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_ext.c#L39)
  - [ocsp_ext.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ocsp/ocsp_ext.c#L353)
- openHiTLS adjacent-only evidence:
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L182)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L201)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L246)
  - [hitls_x509_verify.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_verify/src/hitls_x509_verify.c#L1570)

Batch 235 inventory:
- total interfaces: `137`
- `not_available = 137`
