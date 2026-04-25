# openHiTLS Compatibility Validation Batch 152

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `EVP_CIPHER_asn1_to_param`
- `EVP_CIPHER_do_all`
- `EVP_CIPHER_do_all_provided`
- `EVP_CIPHER_do_all_sorted`
- `EVP_CIPHER_fetch`
- `EVP_CIPHER_free`
- `EVP_CIPHER_get0_description`
- `EVP_CIPHER_get0_name`
- `EVP_CIPHER_get0_provider`
- `EVP_CIPHER_get_asn1_iv`
- `EVP_CIPHER_get_block_size`
- `EVP_CIPHER_get_flags`
- `EVP_CIPHER_get_iv_length`
- `EVP_CIPHER_get_key_length`
- `EVP_CIPHER_get_mode`
- `EVP_CIPHER_get_nid`
- `EVP_CIPHER_get_params`
- `EVP_CIPHER_get_type`
- `EVP_CIPHER_gettable_ctx_params`
- `EVP_CIPHER_gettable_params`
- `EVP_CIPHER_impl_ctx_size`
- `EVP_CIPHER_is_a`
- `EVP_CIPHER_meth_dup`
- `EVP_CIPHER_meth_free`
- `EVP_CIPHER_meth_get_cleanup`
- `EVP_CIPHER_meth_get_ctrl`
- `EVP_CIPHER_meth_get_do_cipher`
- `EVP_CIPHER_meth_get_get_asn1_params`
- `EVP_CIPHER_meth_get_init`
- `EVP_CIPHER_meth_get_set_asn1_params`
- `EVP_CIPHER_meth_new`
- `EVP_CIPHER_meth_set_cleanup`
- `EVP_CIPHER_meth_set_ctrl`
- `EVP_CIPHER_meth_set_do_cipher`
- `EVP_CIPHER_meth_set_flags`
- `EVP_CIPHER_meth_set_get_asn1_params`
- `EVP_CIPHER_meth_set_impl_ctx_size`
- `EVP_CIPHER_meth_set_init`
- `EVP_CIPHER_meth_set_iv_length`
- `EVP_CIPHER_meth_set_set_asn1_params`
- `EVP_CIPHER_names_do_all`
- `EVP_CIPHER_param_to_asn1`
- `EVP_CIPHER_set_asn1_iv`
- `EVP_CIPHER_settable_ctx_params`
- `EVP_CIPHER_up_ref`

Status:
- completed

Initial evidence:
- OpenSSL exposes a full fetched/described/refcounted `EVP_CIPHER` descriptor surface in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L497), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L523), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L526), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L839), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1137), and [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1426).
- openHiTLS exposes public cipher ctx and algorithm-info APIs in [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L69), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L240), and [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L252).
- The public algorithm-info enum only covers a narrow fixed set of properties in [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L902): AEAD flag, stream flag, IV length, key length, and block length.
- No public installed surface was found for:
  - fetching a cipher by name into a reusable descriptor object
  - refcounting/freeing such a descriptor
  - listing all cipher descriptors
  - provider/name/description queries on cipher descriptors
  - `EVP_CIPHER_meth_*` custom method construction/editing
  - generic `OSSL_PARAM` metadata tables for cipher descriptors
  - ASN.1 IV/param helpers on cipher descriptors

Verdict:
- adjust to `partial`:
  - `EVP_CIPHER_get_block_size`
  - `EVP_CIPHER_get_iv_length`
  - `EVP_CIPHER_get_key_length`
  - `EVP_CIPHER_get_params`
- keep `not_available`:
  - the other `41` interfaces in this batch

Reasoning boundary:
- The four `partial` entries only reached `partial` because openHiTLS `CRYPT_EAL_CipherGetInfo` can return a bounded subset of cipher properties by algorithm id.
- The remaining `41` entries stay `not_available` because openHiTLS still does not expose a public `EVP_CIPHER`-style descriptor/name/provider/method surface that developers can directly substitute for the OpenSSL API family.
