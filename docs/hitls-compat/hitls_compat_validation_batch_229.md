# openHiTLS Compatibility Validation Batch 229

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `PBE/KDF parameter wrappers` lacking `analysis_doc`:
  - `i2d_PBE2PARAM`
  - `i2d_PBEPARAM`
  - `i2d_PBKDF2PARAM`
  - `i2d_PBMAC1PARAM`
  - `i2d_SCRYPT_PARAMS`

Status:
- completed

Initial evidence:
- OpenSSL exposes standalone ASN.1 wrapper families for:
  - `PBEPARAM`
  - `PBE2PARAM`
  - `PBKDF2PARAM`
  - `PBMAC1PARAM`
  - `SCRYPT_PARAMS`
- openHiTLS public installed surface exposes algorithm capability for:
  - PBKDF2
  - SCRYPT
  - generic KDF parameter setting
- openHiTLS internal codec utilities also contain PBKDF2-related DER parameter encode/decode templates used by key codecs.
- openHiTLS public installed headers do not expose standalone wrapper-object encoders for these parameter objects.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 5`

Reasoning boundary:
- All 5 interfaces remain `not_available`.
- openHiTLS can perform PBKDF2 / SCRYPT derivation and encode some parameters internally as part of other codec flows.
- That does not create a public standalone encode helper for:
  - `PBE2PARAM`
  - `PBEPARAM`
  - `PBKDF2PARAM`
  - `PBMAC1PARAM`
  - `SCRYPT_PARAMS`
- Practical replaceability fails at the public wrapper-object boundary.

Representative evidence:
- OpenSSL declarations:
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L1030)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L1031)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L1032)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L1033)
  - [x509.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/x509.h.in#L1035)
- openHiTLS public algorithm surfaces:
  - [crypt_pbkdf2.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/pbkdf2/include/crypt_pbkdf2.h#L39)
  - [crypt_pbkdf2.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/pbkdf2/include/crypt_pbkdf2.h#L63)
  - [crypt_scrypt.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/scrypt/include/crypt_scrypt.h#L66)
  - [crypt_scrypt.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/scrypt/include/crypt_scrypt.h#L90)
- openHiTLS internal-only parameter codec evidence:
  - [crypt_codecskey_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_utils.c#L737)
  - [crypt_codecskey_utils.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_utils.c#L995)

Batch 229 inventory:
- total interfaces: `5`
- `not_available = 5`
