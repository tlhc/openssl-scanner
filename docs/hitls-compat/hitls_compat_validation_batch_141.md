# openHiTLS Compatibility Validation Batch 141

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `EVP_PKEY_new_raw_private_key`
- `EVP_PKEY_new_raw_private_key_ex`
- `EVP_PKEY_new_raw_public_key`
- `EVP_PKEY_new_raw_public_key_ex`
- `EVP_PKEY_get_raw_private_key`
- `EVP_PKEY_get_raw_public_key`
- `EVP_PKEY_get_bn_param`
- `X509_PUBKEY_free`
- `X509_PUBKEY_get0_param`

Status:
- completed

Initial evidence:
- OpenSSL publishes the raw-key and pubkey-wrapper surface in [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1806), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1819), [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1950), and [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L1074).
- openHiTLS exposes generic public pkey ctx creation plus raw public/private set/get APIs in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L251), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L278), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L305), and [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L332).
- openHiTLS explicitly exposes ED25519/X25519 raw-key carrying structures and ids in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L47), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L75), and [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L123).
- openHiTLS has no public `X509_PUBKEY` wrapper object surface and no generic string-keyed `EVP_PKEY_get_bn_param` equivalent.

Verdict:
- adjust to `partial`:
  - `EVP_PKEY_new_raw_private_key`
  - `EVP_PKEY_new_raw_private_key_ex`
  - `EVP_PKEY_new_raw_public_key`
  - `EVP_PKEY_new_raw_public_key_ex`
  - `EVP_PKEY_get_raw_private_key`
  - `EVP_PKEY_get_raw_public_key`
- keep `not_available`:
  - `EVP_PKEY_get_bn_param`
  - `X509_PUBKEY_free`
  - `X509_PUBKEY_get0_param`
