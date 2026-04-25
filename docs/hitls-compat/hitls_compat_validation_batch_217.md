# openHiTLS Compatibility Validation Batch 217

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `PKCS8 encode family` lacking `analysis_doc`:
  - `i2d_PKCS8_fp`
  - `i2d_PKCS8_bio`
  - `i2d_PKCS8_PRIV_KEY_INFO`
  - `i2d_PKCS8_PRIV_KEY_INFO_bio`
  - `i2d_PKCS8_PRIV_KEY_INFO_fp`
  - `i2d_PKCS8PrivateKeyInfo_bio`
  - `i2d_PKCS8PrivateKeyInfo_fp`
  - `i2d_PKCS8PrivateKey_bio`
  - `i2d_PKCS8PrivateKey_fp`
  - `i2d_PKCS8PrivateKey_nid_bio`
  - `i2d_PKCS8PrivateKey_nid_fp`

Status:
- completed

Initial evidence:
- OpenSSL exposes several PKCS8 encoding surfaces:
  - `i2d_PKCS8_fp` / `i2d_PKCS8_bio` over `X509_SIG *`
  - `i2d_PKCS8_PRIV_KEY_INFO*` over `PKCS8_PRIV_KEY_INFO *`
  - `i2d_PKCS8PrivateKeyInfo*` over `EVP_PKEY *`
  - `i2d_PKCS8PrivateKey*` and `i2d_PKCS8PrivateKey_nid*` over `EVP_PKEY *` plus encryption / password parameters
- openHiTLS public key codec surface exposes direct PKCS8 encode support:
  - `CRYPT_EAL_EncodeBuffKey`
  - `CRYPT_EAL_ProviderEncodeBuffKey`
  - `CRYPT_EAL_EncodeFileKey`
  - `CRYPT_EAL_ProviderEncodeFileKey`
- The installed public codec contract explicitly supports:
  - `PRIKEY_PKCS8_UNENCRYPT`
  - `PRIKEY_PKCS8_ENCRYPT`
- The implementation dispatches these PKCS8 types through `CRYPT_EAL_PriKeyEncodeBuff`.
- openHiTLS still does not expose OpenSSL wrapper-object encoders for:
  - `X509_SIG *`
  - `PKCS8_PRIV_KEY_INFO *`
- so the practical path is key-context based, not wrapper-object based.

Verdict:
- keep `available = 0`
- adjust to `partial = 11`
- adjust to `not_available = 0`

Reasoning boundary:
- All 11 interfaces become `partial`.
- The public replacement path is real:
  - buffer output:
    - `CRYPT_EAL_EncodeBuffKey(..., CRYPT_PRIKEY_PKCS8_UNENCRYPT, ...)`
    - `CRYPT_EAL_EncodeBuffKey(..., CRYPT_PRIKEY_PKCS8_ENCRYPT, ...)`
  - file output:
    - `CRYPT_EAL_EncodeFileKey(..., CRYPT_PRIKEY_PKCS8_UNENCRYPT, ...)`
    - `CRYPT_EAL_EncodeFileKey(..., CRYPT_PRIKEY_PKCS8_ENCRYPT, ...)`
  - provider forms:
    - `CRYPT_EAL_ProviderEncodeBuffKey`
    - `CRYPT_EAL_ProviderEncodeFileKey`
- These interfaces stay below `available` because:
  - OpenSSL raw `i2d_PKCS8*` APIs encode wrapper objects or `EVP_PKEY *` into OpenSSL cursor / BIO / FILE contracts
  - openHiTLS encodes from `CRYPT_EAL_PkeyCtx *`
  - OpenSSL `_nid_` and cipher/password callbacks do not have the same public helper shape in openHiTLS
  - there is no public `X509_SIG` or `PKCS8_PRIV_KEY_INFO` object-model parity

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L412)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L413)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L418)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L419)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L462)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L463)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L468)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L469)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L551)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L1076)
  - [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L499)
  - [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L502)
  - [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L509)
  - [pem.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/pem.h#L512)
- OpenSSL implementations:
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L695)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L706)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L743)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L749)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L823)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L829)
  - [pem_pk8.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_pk8.c#L55)
  - [pem_pk8.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_pk8.c#L62)
  - [pem_pk8.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_pk8.c#L207)
  - [pem_pk8.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_pk8.c#L214)
- openHiTLS public declarations:
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L311)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L327)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L357)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L298)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L299)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L917)
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L918)
- openHiTLS implementations:
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L579)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L603)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L611)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L680)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L722)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L730)

Batch 217 inventory:
- total interfaces: `11`
- `partial = 11`
