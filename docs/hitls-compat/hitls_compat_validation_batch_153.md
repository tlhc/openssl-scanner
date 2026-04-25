# openHiTLS Compatibility Validation Batch 153

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `EVP_MD_CTX_*` entries lacking `analysis_doc`
- all remaining `EVP_MD_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a full fetched/refcounted `EVP_MD` descriptor surface and rich `EVP_MD_CTX` metadata/control surface in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L612), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L620), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L621), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L627), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L629), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L647), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1150), and [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1519).
- openHiTLS exposes the public MD ctx surface in [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L61), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L81), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L92), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L104), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L114), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L124), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L139), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L171), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L181), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L213), and [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L224).
- That public surface gives direct ctx copy/dup/deinit and digest-size queries, but it still does not expose:
  - an `EVP_MD` descriptor object
  - by-name/provider fetch and refcounting for digests
  - `EVP_MD_meth_*` custom method construction
  - generic `OSSL_PARAM` metadata tables for digest descriptors or digest ctx
  - `EVP_MD_CTX` flags / ctrl / update-fn / attached pkey ctx metadata

Verdict:
- adjust to `available`:
  - `EVP_MD_CTX_copy`
  - `EVP_MD_CTX_copy_ex`
  - `EVP_MD_CTX_dup`
  - `EVP_MD_CTX_reset`
- adjust to `partial`:
  - `EVP_MD_CTX_get0_md`
  - `EVP_MD_get_size`
- keep `not_available`:
  - the other `56` interfaces in this batch

Reasoning boundary:
- The four `available` entries all have direct public MD ctx lifecycle/copy analogues in openHiTLS.
- `EVP_MD_CTX_get0_md` only reached `partial` because openHiTLS can return the digest algorithm id from the ctx, but not an `EVP_MD` descriptor object.
- `EVP_MD_get_size` only reached `partial` because openHiTLS can return digest size by algorithm id, but not from a fetched `EVP_MD` descriptor.
- The remaining `56` entries stay `not_available` because openHiTLS still lacks the public `EVP_MD` descriptor/fetch/provider/method/metadata surface that those OpenSSL APIs fundamentally depend on.
