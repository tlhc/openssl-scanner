# openHiTLS Compatibility Validation Batch 154

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `EVP_KDF_*` entries lacking `analysis_doc`
- all remaining `EVP_KDF_CTX_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a fetched/refcounted `EVP_KDF` descriptor surface and a separate `EVP_KDF_CTX` context surface in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1240), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1812), and [kdf_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/kdf_lib.c#L24).
- openHiTLS exposes only the public KDF context surface in [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L60), [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L69), [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L81), [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L94), [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L105), [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L114), [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L125), and [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L135).
- There is no public installed surface for:
  - fetched/refcounted `EVP_KDF` descriptor objects
  - KDF descriptor name/description/provider metadata
  - descriptor enumeration / `is_a`
  - gettable/settable metadata tables for KDF descriptors or KDF contexts
  - KDF context parameter-readback
  - fixed-output-size query

Verdict:
- adjust to `available`:
  - `EVP_KDF_CTX_dup`
  - `EVP_KDF_CTX_free`
  - `EVP_KDF_CTX_reset`
  - `EVP_KDF_CTX_set_params`
  - `EVP_KDF_derive`
- adjust to `partial`:
  - `EVP_KDF_CTX_new`
- keep `not_available`:
  - the other `18` interfaces in this batch

Reasoning boundary:
- The five `available` entries all have direct public KDF context lifecycle or derive/set-param analogues in openHiTLS.
- `EVP_KDF_CTX_new` only reached `partial` because openHiTLS creates KDF contexts by algorithm id, not from a fetched `EVP_KDF` descriptor object.
- The remaining `18` entries stay `not_available` because openHiTLS does not expose the public `EVP_KDF` descriptor/fetch/provider/metadata surface or the KDF context parameter-readback/metadata APIs that those OpenSSL interfaces fundamentally depend on.
