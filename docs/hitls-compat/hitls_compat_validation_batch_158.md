# openHiTLS Compatibility Validation Batch 158

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `EVP_PKEY_CTX_dup`
- `EVP_PKEY_CTX_get_data`
- `EVP_PKEY_CTX_set_data`
- `EVP_PKEY_CTX_get_app_data`
- `EVP_PKEY_CTX_set_app_data`
- `EVP_PKEY_CTX_get0_pkey`
- `EVP_PKEY_CTX_get0_peerkey`
- `EVP_PKEY_CTX_get0_libctx`
- `EVP_PKEY_CTX_get0_propq`
- `EVP_PKEY_CTX_get0_provider`
- `EVP_PKEY_CTX_get_operation`
- `EVP_PKEY_CTX_new_from_name`
- `EVP_PKEY_CTX_new_from_pkey`
- `EVP_PKEY_CTX_is_a`

Status:
- completed

Initial evidence:
- OpenSSL exposes the core pkey-context lifecycle/data getters and provider-oriented constructors in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1643), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1648), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1650), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1673), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1703), and [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1922).
- openHiTLS exposes direct public pkey-context duplication and ext-data APIs in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L172), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L675), and [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L686).
- openHiTLS also exposes provider-aware pkey context creation in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L146), but not by public algorithm-name lookup and not from an existing fetched key object in the OpenSSL sense.
- No public getters were found for bound key object, peer key object, provider libctx, propq, provider descriptor, or current operation state on the pkey-context surface.

Verdict:
- adjust to `available`:
  - `EVP_PKEY_CTX_dup`
  - `EVP_PKEY_CTX_get_data`
  - `EVP_PKEY_CTX_set_data`
  - `EVP_PKEY_CTX_get_app_data`
  - `EVP_PKEY_CTX_set_app_data`
- keep `not_available`:
  - `EVP_PKEY_CTX_get0_pkey`
  - `EVP_PKEY_CTX_get0_peerkey`
  - `EVP_PKEY_CTX_get0_libctx`
  - `EVP_PKEY_CTX_get0_propq`
  - `EVP_PKEY_CTX_get0_provider`
  - `EVP_PKEY_CTX_get_operation`
  - `EVP_PKEY_CTX_new_from_name`
  - `EVP_PKEY_CTX_new_from_pkey`
  - `EVP_PKEY_CTX_is_a`

Reasoning boundary:
- The five `available` entries all have direct public pkey-context duplication or ext-data analogues in openHiTLS.
- The remaining nine stay `not_available` because openHiTLS does not expose the corresponding bound-object/provider/operation/identity surfaces that OpenSSL makes visible on `EVP_PKEY_CTX`.
