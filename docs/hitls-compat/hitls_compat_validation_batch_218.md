# openHiTLS Compatibility Validation Batch 218

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `legacy key / param encode family` lacking `analysis_doc`:
  - `i2d_RSA_OAEP_PARAMS`
  - `i2d_RSA_PSS_PARAMS`
  - `i2d_RSA_PUBKEY`
  - `i2d_RSA_PUBKEY_bio`
  - `i2d_RSA_PUBKEY_fp`
  - `i2d_DSA_PUBKEY`
  - `i2d_DSA_PUBKEY_bio`
  - `i2d_DSA_PUBKEY_fp`
  - `i2d_DSA_SIG`
  - `i2d_ECDSA_SIG`
  - `i2d_ECPKParameters`
  - `i2d_ECParameters`
  - `i2d_ECPrivateKey`
  - `i2d_ECPrivateKey_bio`
  - `i2d_ECPrivateKey_fp`
  - `i2d_EC_PUBKEY`
  - `i2d_EC_PUBKEY_bio`
  - `i2d_EC_PUBKEY_fp`
  - `i2d_DHparams`
  - `i2d_DHxparams`

Status:
- completed

Initial evidence:
- OpenSSL exposes public encoders for:
  - `RSA_PUBKEY`
  - `DSA_PUBKEY`
  - `DSA_SIG`
  - `ECDSA_SIG`
  - `ECPKParameters`
  - `ECParameters`
  - `ECPrivateKey`
  - `EC_PUBKEY`
  - `DHparams`
  - `DHxparams`
  - `RSA_OAEP_PARAMS`
  - `RSA_PSS_PARAMS`
- openHiTLS public key-codec encode surface exposes only these relevant installed encode types:
  - `CRYPT_PRIKEY_RSA`
  - `CRYPT_PRIKEY_ECC`
  - `CRYPT_PUBKEY_RSA`
  - `CRYPT_PUBKEY_SUBKEY`
  - `CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ`
- openHiTLS codec implementation contains internal DSA/DH/ECC helper encoders, but the public installed type list does not expose DSA or DH encode types.
- openHiTLS public surface also does not expose standalone ASN.1 object encoders for:
  - `DSA_SIG`
  - `ECDSA_SIG`
  - `RSA_OAEP_PARAMS`
  - `RSA_PSS_PARAMS`
  - curve / DH parameter wrapper objects

Verdict:
- keep `available = 0`
- adjust to `partial = 9`
- adjust to `not_available = 11`

Reasoning boundary:
- `partial` is justified for the interfaces that map onto the installed key-codec encode surface:
  - `i2d_RSA_PUBKEY`
  - `i2d_RSA_PUBKEY_bio`
  - `i2d_RSA_PUBKEY_fp`
  - `i2d_ECPrivateKey`
  - `i2d_ECPrivateKey_bio`
  - `i2d_ECPrivateKey_fp`
  - `i2d_EC_PUBKEY`
  - `i2d_EC_PUBKEY_bio`
  - `i2d_EC_PUBKEY_fp`
- Practical replacement path:
  - RSA public key: `CRYPT_EAL_EncodeBuffKey` / `CRYPT_EAL_EncodeFileKey` with `CRYPT_PUBKEY_RSA`
  - EC private key: `CRYPT_EAL_EncodeBuffKey` / `CRYPT_EAL_EncodeFileKey` with `CRYPT_PRIKEY_ECC`
  - EC public key: `CRYPT_EAL_EncodeBuffKey` / `CRYPT_EAL_EncodeFileKey` with `CRYPT_PUBKEY_SUBKEY`
- These remain `partial` because the public contract is key-context based, not OpenSSL `RSA *` / `EC_KEY *` / `BIO *` / `FILE *`.
- `not_available` remains correct for:
  - `i2d_DSA_PUBKEY*`
  - `i2d_DSA_SIG`
  - `i2d_ECDSA_SIG`
  - `i2d_ECPKParameters`
  - `i2d_ECParameters`
  - `i2d_DHparams`
  - `i2d_DHxparams`
  - `i2d_RSA_OAEP_PARAMS`
  - `i2d_RSA_PSS_PARAMS`
- The missing piece is the public installed encode type / standalone wrapper-object encoder surface for DSA, DH, signature objects, and parameter objects.

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L394)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L399)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L407)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L409)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L442)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L447)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L456)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L458)
  - [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L932)
  - [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1210)
  - [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1234)
  - [dh.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/dh.h#L182)
  - [dh.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/dh.h#L194)
- OpenSSL implementations:
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L404)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L435)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L457)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L478)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L492)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L502)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L512)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L522)
  - [x_pubkey.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_pubkey.c#L615)
  - [x_pubkey.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_pubkey.c#L764)
  - [x_pubkey.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_pubkey.c#L809)
  - [ec_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ec/ec_asn1.c#L910)
  - [ec_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ec/ec_asn1.c#L1021)
  - [ec_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ec/ec_asn1.c#L1091)
  - [ec_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ec/ec_asn1.c#L1246)
  - [dsa_sign.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/dsa/dsa_sign.c#L78)
  - [dh_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/dh/dh_asn1.c#L137)
- openHiTLS public declarations:
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L921)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L922)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L923)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L924)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L925)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L311)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L327)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L357)
- openHiTLS implementations:
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L579)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L603)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L611)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L617)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L680)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L722)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L730)
  - [crypt_codecskey_local.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_local.c#L457)
  - [crypt_codecskey_local.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_local.c#L598)
  - [crypt_codecskey_local.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_local.c#L1473)
  - [crypt_codecskey_local.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_local.c#L1495)

Batch 218 inventory:
- total interfaces: `20`
- `partial = 9`
- `not_available = 11`
