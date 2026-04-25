# openHiTLS Compatibility Validation Batch 220

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `i2d_TS_*` family lacking `analysis_doc`:
  - `i2d_TS_ACCURACY`
  - `i2d_TS_MSG_IMPRINT`
  - `i2d_TS_MSG_IMPRINT_bio`
  - `i2d_TS_MSG_IMPRINT_fp`
  - `i2d_TS_REQ`
  - `i2d_TS_REQ_bio`
  - `i2d_TS_REQ_fp`
  - `i2d_TS_RESP`
  - `i2d_TS_RESP_bio`
  - `i2d_TS_RESP_fp`
  - `i2d_TS_STATUS_INFO`
  - `i2d_TS_TST_INFO`
  - `i2d_TS_TST_INFO_bio`
  - `i2d_TS_TST_INFO_fp`

Status:
- completed

Initial evidence:
- OpenSSL exposes a dedicated timestamp ASN.1 object family and encode helpers through public `TS_*` declarations and implementations:
  - `i2d_TS_REQ_*`
  - `i2d_TS_MSG_IMPRINT_*`
  - `i2d_TS_RESP_*`
  - `i2d_TS_TST_INFO_*`
  - plus standalone timestamp wrapper objects such as `TS_ACCURACY` and `TS_STATUS_INFO`
- openHiTLS public installed tree has no timestamp protocol object family and no TS encode surface.
- The only `ts`-like matches in openHiTLS are unrelated entropy timestamp source code and notary-free OID-adjacent infrastructure.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 14`

Reasoning boundary:
- All 14 interfaces remain `not_available`.
- OpenSSL side is a standalone timestamp ASN.1 object encode family.
- openHiTLS public installed headers do not provide:
  - `TS_REQ` / `TS_RESP` / `TS_TST_INFO` object creation
  - timestamp request / response / imprint object encode helpers
  - any public timestamp protocol encode surface
- Unrelated entropy timestamp code does not create a practical replacement path.

Representative evidence:
- OpenSSL declarations:
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L75)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L78)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L86)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L89)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L97)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L100)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L113)
  - [ts.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ts.h#L116)
- OpenSSL implementation evidence:
  - [ts_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_asn1.c#L28)
  - [ts_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_asn1.c#L61)
  - [ts_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_asn1.c#L107)
  - [ts_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_asn1.c#L187)
  - [ts_rsp_sign.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_rsp_sign.c#L381)
  - [ts_rsp_sign.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ts/ts_rsp_sign.c#L543)
- openHiTLS absence / adjacent-only evidence:
  - [crypt_entropy.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/entropy/include/crypt_entropy.h#L59)
  - [es_ns_timestamp.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/entropy/src/es_ns_timestamp.c#L52)
  - [hitls_pki_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_types.h#L311)
  - [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L182)

Batch 220 inventory:
- total interfaces: `14`
- `not_available = 14`
