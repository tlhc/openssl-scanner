# openHiTLS Compatibility Validation Batch 236

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `TS_*` family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a complete timestamp object/helper family in public headers and `crypto/ts`, including:
  - object constructors / destructors / dup helpers
  - request / response / context setup
  - print helpers
  - ext accessors / mutators
  - response-signing and verification-context helpers
- openHiTLS public installed tree has no timestamp protocol object family and no TS helper surface.
- openHiTLS only has unrelated entropy timestamp source code and no PKI timestamp protocol implementation surface.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 155`

Reasoning boundary:
- All `155` interfaces remain `not_available`.
- OpenSSL side here is a standalone timestamp protocol subsystem.
- openHiTLS public installed headers do not provide:
  - `TS_REQ` / `TS_RESP` / `TS_TST_INFO` object APIs
  - `TS_RESP_CTX` / `TS_VERIFY_CTX` helper surfaces
  - timestamp ext / print helpers
  - request / response / verification workflows
- Unrelated entropy timestamp code does not create a practical replacement path.

Representative evidence:
- OpenSSL declarations:
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L122)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L153)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L269)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L414)
- OpenSSL implementation evidence:
  - [ts_verify_ctx.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_verify_ctx.c#L15)
  - [ts_rsp_sign.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_rsp_sign.c#L93)
  - [ts_req_utils.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_req_utils.c#L17)
  - [ts_rsp_utils.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_rsp_utils.c#L17)
  - [ts_req_print.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_req_print.c#L18)
  - [ts_rsp_print.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_rsp_print.c#L27)
  - [ts_conf.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_conf.c#L130)
- openHiTLS absence / adjacent-only evidence:
  - [crypt_entropy.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/entropy/include/crypt_entropy.h#L59)
  - [es_ns_timestamp.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/entropy/src/es_ns_timestamp.c#L52)

Batch 236 inventory:
- total interfaces: `155`
- `not_available = 155`
