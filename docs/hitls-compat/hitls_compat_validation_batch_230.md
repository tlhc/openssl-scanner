# openHiTLS Compatibility Validation Batch 230

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `generic/legacy key encode family` lacking `analysis_doc`:
  - `i2d_PUBKEY`
  - `i2d_PUBKEY_bio`
  - `i2d_PUBKEY_fp`
  - `i2d_PrivateKey`
  - `i2d_PrivateKey_bio`
  - `i2d_PrivateKey_fp`
  - `i2d_PublicKey`
  - `i2d_RSAPrivateKey`
  - `i2d_RSAPrivateKey_bio`
  - `i2d_RSAPrivateKey_fp`
  - `i2d_RSAPublicKey`
  - `i2d_RSAPublicKey_bio`
  - `i2d_RSAPublicKey_fp`

Status:
- completed

Initial evidence:
- OpenSSL exposes generic `EVP_PKEY` encoders:
  - `i2d_PublicKey`
  - `i2d_PrivateKey`
  - `i2d_PUBKEY`
  - plus BIO / FILE wrappers
- OpenSSL also exposes RSA-specific encoders:
  - `i2d_RSAPrivateKey`
  - `i2d_RSAPublicKey`
  - plus BIO / FILE wrappers
- openHiTLS public key-codec encode surface exposes installed encode types:
  - `CRYPT_PRIKEY_RSA`
  - `CRYPT_PRIKEY_ECC`
  - `CRYPT_PUBKEY_RSA`
  - `CRYPT_PUBKEY_SUBKEY`
  - `CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ`
- openHiTLS public encode entrypoints are:
  - `CRYPT_EAL_EncodeBuffKey`
  - `CRYPT_EAL_ProviderEncodeBuffKey`
  - `CRYPT_EAL_EncodeFileKey`
  - `CRYPT_EAL_ProviderEncodeFileKey`
- The key codec implementation routes RSA/ECC private keys through `CRYPT_EAL_PriKeyEncodeBuff`
  and public keys through `CRYPT_EAL_PubKeyEncodeBuff`.

Verdict:
- keep `available = 0`
- adjust to `partial = 13`
- adjust to `not_available = 0`

Reasoning boundary:
- All 13 interfaces become `partial`.
- Public practical replacement exists for the supported key families:
  - generic public key encode:
    - `CRYPT_EAL_EncodeBuffKey(..., CRYPT_PUBKEY_SUBKEY / CRYPT_PUBKEY_RSA, ...)`
    - `CRYPT_EAL_EncodeFileKey(..., CRYPT_PUBKEY_SUBKEY / CRYPT_PUBKEY_RSA, ...)`
  - generic private key encode:
    - `CRYPT_EAL_EncodeBuffKey(..., CRYPT_PRIKEY_RSA / CRYPT_PRIKEY_ECC, ...)`
    - `CRYPT_EAL_EncodeFileKey(..., CRYPT_PRIKEY_RSA / CRYPT_PRIKEY_ECC, ...)`
  - RSA-specific legacy encode:
    - `CRYPT_EAL_EncodeBuffKey(..., CRYPT_PRIKEY_RSA / CRYPT_PUBKEY_RSA, ...)`
    - `CRYPT_EAL_EncodeFileKey(..., CRYPT_PRIKEY_RSA / CRYPT_PUBKEY_RSA, ...)`
- These remain `partial` because:
  - OpenSSL contracts operate on `EVP_PKEY *` or `RSA *`
  - `_bio` / `_fp` helper contracts are not preserved directly
  - `i2d_PublicKey` and `i2d_PrivateKey` are generic across more legacy key families than openHiTLS publicly exposes
  - openHiTLS replacement is key-context based and algorithm-limited to the installed encode types

Representative evidence:
- OpenSSL declarations:
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1347)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1359)
- OpenSSL implementations:
  - [i2d_evp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/i2d_evp.c#L131)
  - [i2d_evp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/i2d_evp.c#L141)
  - [i2d_evp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/i2d_evp.c#L156)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L762)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L788)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L842)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L871)
  - [rsa_ameth.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/rsa/rsa_ameth.c#L62)
  - [rsa_ameth.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/rsa/rsa_ameth.c#L142)
- openHiTLS public declarations:
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L311)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L327)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L357)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L921)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L922)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L923)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L924)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L925)
- openHiTLS implementation evidence:
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L579)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L603)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L611)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L617)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L679)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L722)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L730)

Batch 230 inventory:
- total interfaces: `13`
- `partial = 13`
