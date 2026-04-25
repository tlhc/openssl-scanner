# openHiTLS Compatibility Validation Batch 227

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `DSA legacy encode family` lacking `analysis_doc`:
  - `i2d_DSAPrivateKey`
  - `i2d_DSAPrivateKey_bio`
  - `i2d_DSAPrivateKey_fp`
  - `i2d_DSAPublicKey`
  - `i2d_DSAparams`

Status:
- completed

Initial evidence:
- OpenSSL exposes public encode helpers for legacy DSA objects and params:
  - `i2d_DSAparams`
  - `i2d_DSAPrivateKey`
  - `i2d_DSAPublicKey`
  - plus BIO / FILE wrappers
- openHiTLS contains internal DSA ASN.1 encode helpers such as `EncodeDsaKeyParamAsn1Buff`.
- openHiTLS installed public encode types do not expose DSA-specific key encode targets.
- The public installed encode type list stops at:
  - `CRYPT_PRIKEY_RSA`
  - `CRYPT_PRIKEY_ECC`
  - `CRYPT_PUBKEY_SUBKEY`
  - `CRYPT_PUBKEY_RSA`
  - `CRYPT_PUBKEY_SUBKEY_WITHOUT_SEQ`

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 5`

Reasoning boundary:
- All 5 interfaces remain `not_available`.
- Internal helper presence is insufficient because there is no public installed DSA encode surface.
- OpenSSL side requires:
  - standalone `DSA *` private/public key encoders
  - standalone `DSAparams` encoder
  - BIO / FILE helper wrappers
- openHiTLS public practical replacement path does not exist for these legacy DSA objects.

Representative evidence:
- OpenSSL declarations:
  - [dsa.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/dsa.h#L109)
  - [dsa.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/dsa.h#L113)
  - [dsa.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/dsa.h#L116)
- OpenSSL implementations:
  - [dsa_asn1.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/dsa/dsa_asn1.c#L56)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L447)
  - [x_all.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/x509/x_all.c#L468)
  - [i2d_evp.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/i2d_evp.c#L158)
- openHiTLS internal-only evidence:
  - [crypt_codecskey_local.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_local.c#L457)
- openHiTLS public encode-type boundary:
  - [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L917)

Batch 227 inventory:
- total interfaces: `5`
- `not_available = 5`
