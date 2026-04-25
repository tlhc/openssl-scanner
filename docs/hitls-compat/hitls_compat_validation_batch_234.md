# openHiTLS Compatibility Validation Batch 234

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `EVP_PKEY key-parameter encoders` lacking `analysis_doc`:
  - `i2d_KeyParams`
  - `i2d_KeyParams_bio`

Status:
- completed

Initial evidence:
- OpenSSL exposes generic key-parameter encoders:
  - `i2d_KeyParams`
  - `i2d_KeyParams_bio`
- openHiTLS public installed key-management surface exposes parameter control APIs:
  - `CRYPT_EAL_PkeySetParaEx`
  - `CRYPT_EAL_PkeySetPubEx`
  - `CRYPT_EAL_PkeySetPrvEx`
  - `CRYPT_EAL_PkeyGetPubEx`
  - `CRYPT_EAL_PkeyGetPrvEx`
- openHiTLS public installed encode surface exposes only whole-key encoders:
  - `CRYPT_EAL_EncodeBuffKey`
  - `CRYPT_EAL_ProviderEncodeBuffKey`
  - `CRYPT_EAL_EncodeFileKey`
  - `CRYPT_EAL_ProviderEncodeFileKey`
- openHiTLS internal codec utilities contain parameter encoding machinery, but there is no public installed standalone key-parameter encoder.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 2`

Reasoning boundary:
- Both interfaces remain `not_available`.
- openHiTLS public APIs can manage parameters on key contexts.
- openHiTLS public APIs can encode whole keys.
- There is no public installed API that encodes only the parameter subset of an `EVP_PKEY` analogue.
- Practical replaceability therefore fails at the standalone key-parameter encode boundary.

Representative evidence:
- OpenSSL declarations:
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1362)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1365)
- OpenSSL implementations:
  - [i2d_evp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/i2d_evp.c#L73)
  - [i2d_evp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/i2d_evp.c#L91)
  - [d2i_param.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/d2i_param.c#L18)
  - [d2i_param.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/d2i_param.c#L49)
- openHiTLS public installed parameter/key surfaces:
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L204)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L266)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L293)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L320)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L347)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L311)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L327)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L357)
- openHiTLS internal-only parameter codec evidence:
  - [crypt_codecskey_local.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_local.c#L274)
  - [crypt_codecskey_local.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_local.c#L457)
  - [crypt_codecskey_local.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_local.c#L598)

Batch 234 inventory:
- total interfaces: `2`
- `not_available = 2`
