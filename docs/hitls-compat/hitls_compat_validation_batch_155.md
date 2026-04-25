# openHiTLS Compatibility Validation Batch 155

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `EVP_MAC_*` entries lacking `analysis_doc`
- all remaining `EVP_MAC_CTX_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a fetched/refcounted `EVP_MAC` descriptor surface and a separate `EVP_MAC_CTX` context surface in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1159) and [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1169).
- openHiTLS exposes only the public MAC context surface in [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L50), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L62), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L70), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L92), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L109), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L143), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L158), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L170), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L181), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L198), [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L213), and [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L228).
- There is no public installed surface for:
  - fetched/refcounted `EVP_MAC` descriptor objects
  - MAC descriptor name/description/provider metadata
  - descriptor enumeration / `is_a`
  - gettable/settable metadata tables for MAC descriptors or MAC contexts
  - MAC context parameter-readback
  - XOF-style MAC finalization

Verdict:
- adjust to `available`:
  - `EVP_MAC_CTX_dup`
  - `EVP_MAC_CTX_free`
  - `EVP_MAC_CTX_get_mac_size`
  - `EVP_MAC_final`
  - `EVP_MAC_init`
  - `EVP_MAC_update`
- adjust to `partial`:
  - `EVP_MAC_CTX_new`
  - `EVP_MAC_CTX_set_params`
- keep `not_available`:
  - the other `19` interfaces in this batch

Reasoning boundary:
- The six `available` entries all have direct public MAC context lifecycle or operation analogues in openHiTLS.
- `EVP_MAC_CTX_new` only reached `partial` because openHiTLS creates MAC contexts by algorithm id, not from a fetched `EVP_MAC` descriptor object.
- `EVP_MAC_CTX_set_params` only reached `partial` because openHiTLS `CRYPT_EAL_MacSetParam` exists, but it only covers a bounded subset of MAC parameter surfaces.
- The remaining `19` entries stay `not_available` because openHiTLS does not expose the public `EVP_MAC` descriptor/fetch/provider/metadata surface or MAC context metadata/readback APIs that those OpenSSL interfaces fundamentally depend on.
