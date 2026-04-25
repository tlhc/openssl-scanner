# openHiTLS Compatibility Validation Batch 205

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining legacy key-decode `d2i_*` family with a practical public decode path or a clear public gap:
  - `RSA`
  - `DSA`
  - `EC`
  - generic `d2i_PublicKey`

Status:
- completed

Initial evidence:
- OpenSSL exposes dedicated legacy key decode helpers such as:
  - `d2i_RSAPrivateKey`
  - `d2i_RSAPublicKey`
  - `d2i_RSA_PUBKEY`
  - `d2i_DSAPrivateKey`
  - `d2i_DSAPublicKey`
  - `d2i_DSA_PUBKEY`
  - `d2i_ECPrivateKey`
  - `d2i_EC_PUBKEY`
  - `d2i_PublicKey`
- openHiTLS public key-codec surfaces expose:
  - `CRYPT_EAL_DecodeBuffKey`
  - `CRYPT_EAL_DecodeFileKey`
  - with concrete decode types such as:
    - `CRYPT_PRIKEY_RSA`
    - `CRYPT_PRIKEY_ECC`
    - `CRYPT_PUBKEY_RSA`
    - `CRYPT_PUBKEY_SUBKEY`
- openHiTLS public decode types do not include a dedicated raw DSA private/public key helper surface.

Verdict:
- keep `available = 0`
- adjust to `partial = 19`
- adjust to `not_available = 4`

Reasoning boundary:
- `partial` is used where a public legacy key decode path exists but returns `CRYPT_EAL_PkeyCtx` and differs from the OpenSSL object and cursor model:
  - RSA raw private/public
  - RSA SubjectPublicKeyInfo
  - DSA SubjectPublicKeyInfo
  - EC raw private
  - EC SubjectPublicKeyInfo
  - generic `d2i_PublicKey`
- `not_available` is used where openHiTLS has no public raw legacy DSA decode helper surface:
  - `d2i_DSAPrivateKey`
  - `d2i_DSAPrivateKey_bio`
  - `d2i_DSAPrivateKey_fp`
  - `d2i_DSAPublicKey`
