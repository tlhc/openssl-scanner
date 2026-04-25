# openHiTLS Compatibility Validation Batch 151

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `EVP_CIPHER_CTX_buf_noconst`
- `EVP_CIPHER_CTX_cipher`
- `EVP_CIPHER_CTX_clear_flags`
- `EVP_CIPHER_CTX_copy`
- `EVP_CIPHER_CTX_dup`
- `EVP_CIPHER_CTX_get0_cipher`
- `EVP_CIPHER_CTX_get1_cipher`
- `EVP_CIPHER_CTX_get_app_data`
- `EVP_CIPHER_CTX_get_block_size`
- `EVP_CIPHER_CTX_get_cipher_data`
- `EVP_CIPHER_CTX_get_iv_length`
- `EVP_CIPHER_CTX_get_key_length`
- `EVP_CIPHER_CTX_get_nid`
- `EVP_CIPHER_CTX_get_num`
- `EVP_CIPHER_CTX_get_original_iv`
- `EVP_CIPHER_CTX_get_params`
- `EVP_CIPHER_CTX_get_tag_length`
- `EVP_CIPHER_CTX_get_updated_iv`
- `EVP_CIPHER_CTX_gettable_params`
- `EVP_CIPHER_CTX_is_encrypting`
- `EVP_CIPHER_CTX_iv`
- `EVP_CIPHER_CTX_iv_noconst`
- `EVP_CIPHER_CTX_original_iv`
- `EVP_CIPHER_CTX_rand_key`
- `EVP_CIPHER_CTX_reset`
- `EVP_CIPHER_CTX_set_app_data`
- `EVP_CIPHER_CTX_set_cipher_data`
- `EVP_CIPHER_CTX_set_flags`
- `EVP_CIPHER_CTX_set_num`
- `EVP_CIPHER_CTX_set_params`
- `EVP_CIPHER_CTX_settable_params`
- `EVP_CIPHER_CTX_test_flags`

Status:
- completed

Initial evidence:
- OpenSSL exposes the full `EVP_CIPHER_CTX_*` helper family in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L529), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L561), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L677), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L830), and [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L837).
- openHiTLS exposes the public cipher ctx surface in [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L79), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L114), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L127), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L231), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L240), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L252), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L264), and [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L274).
- The public cipher ctrl/algorithm-info enums that bound the practical replacement surface are in [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L600) and [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L902).

Verdict:
- adjust to `available`:
  - `EVP_CIPHER_CTX_copy`
  - `EVP_CIPHER_CTX_dup`
  - `EVP_CIPHER_CTX_get_block_size`
  - `EVP_CIPHER_CTX_reset`
- adjust to `partial`:
  - `EVP_CIPHER_CTX_get_params`
  - `EVP_CIPHER_CTX_get_updated_iv`
  - `EVP_CIPHER_CTX_set_params`
- keep `not_available`:
  - `EVP_CIPHER_CTX_buf_noconst`
  - `EVP_CIPHER_CTX_cipher`
  - `EVP_CIPHER_CTX_clear_flags`
  - `EVP_CIPHER_CTX_get0_cipher`
  - `EVP_CIPHER_CTX_get1_cipher`
  - `EVP_CIPHER_CTX_get_app_data`
  - `EVP_CIPHER_CTX_get_cipher_data`
  - `EVP_CIPHER_CTX_get_iv_length`
  - `EVP_CIPHER_CTX_get_key_length`
  - `EVP_CIPHER_CTX_get_nid`
  - `EVP_CIPHER_CTX_get_num`
  - `EVP_CIPHER_CTX_get_original_iv`
  - `EVP_CIPHER_CTX_get_tag_length`
  - `EVP_CIPHER_CTX_gettable_params`
  - `EVP_CIPHER_CTX_is_encrypting`
  - `EVP_CIPHER_CTX_iv`
  - `EVP_CIPHER_CTX_iv_noconst`
  - `EVP_CIPHER_CTX_original_iv`
  - `EVP_CIPHER_CTX_rand_key`
  - `EVP_CIPHER_CTX_set_app_data`
  - `EVP_CIPHER_CTX_set_cipher_data`
  - `EVP_CIPHER_CTX_set_flags`
  - `EVP_CIPHER_CTX_set_num`
  - `EVP_CIPHER_CTX_settable_params`
  - `EVP_CIPHER_CTX_test_flags`

Reasoning boundary:
- The four `available` entries all have direct public ctx-level analogues in openHiTLS.
- The three `partial` entries only reached `partial` because openHiTLS `CipherCtrl` covers a bounded subset of ctx parameters such as IV, AAD, tag, tag length, message length, feedback size, and block size, but not OpenSSL's generic OSSL_PARAM surface.
- The rest remain `not_available` because openHiTLS still does not expose public ctx descriptor getters, app-data slots, raw internal-buffer accessors, flag APIs, or the specific metadata/query helpers those OpenSSL interfaces require.
