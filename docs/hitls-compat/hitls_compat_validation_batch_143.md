# openHiTLS Compatibility Validation Batch 143

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `BIO_flush`
- `BIO_get_mem_ptr`
- `BIO_clear_retry_flags`
- `BIO_set_nbio`
- `BIO_number_written`
- `BIO_set_init`
- `BIO_vfree`
- `OPENSSL_malloc`
- `OPENSSL_clear_free`
- `OPENSSL_strdup`
- `EVP_EncodeInit`
- `EVP_EncodeUpdate`
- `EVP_EncodeFinal`
- `EVP_MD_CTX_set_flags`
- `EVP_MD_CTX_init`
- `EVP_MD_CTX_create`
- `EVP_MD_CTX_destroy`
- `EVP_VerifyInit_ex`
- `EVP_VerifyUpdate`
- `EVP_get_digestbynid`
- `EVP_MD_type`
- `EVP_PKEY_id`

Status:
- completed

Initial evidence:
- OpenSSL exposes the BIO/UIO helpers and Base64/EVP helpers in [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L272), [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L492), [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L604), [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L627), [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L699), [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L722), [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L726), and [evp/encode.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/encode.c#L367).
- openHiTLS exposes the corresponding public UIO surfaces in [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L111), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L121), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L177), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L237), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L346), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L354), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L441), [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L480), and [bsl_buffer.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/buffer/include/bsl_buffer.h#L28).
- openHiTLS exposes the corresponding public memory/Base64 helpers in [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L214), [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L239), [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L283), [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L104), [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L118), and [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L129).
- openHiTLS exposes the corresponding public digest/pkey helpers in [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L81), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L104), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L114), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L124), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L139), and [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L639).

Verdict:
- adjust to `available`:
  - `BIO_set_init`
  - `BIO_vfree`
  - `OPENSSL_malloc`
  - `OPENSSL_clear_free`
  - `EVP_EncodeInit`
  - `EVP_EncodeUpdate`
  - `EVP_EncodeFinal`
  - `EVP_MD_CTX_destroy`
- adjust to `partial`:
  - `BIO_flush`
  - `BIO_get_mem_ptr`
  - `BIO_clear_retry_flags`
  - `BIO_number_written`
  - `OPENSSL_strdup`
  - `EVP_MD_CTX_init`
  - `EVP_MD_CTX_create`
  - `EVP_VerifyInit_ex`
  - `EVP_VerifyUpdate`
  - `EVP_MD_type`
  - `EVP_PKEY_id`
- keep `not_available`:
  - `BIO_set_nbio`
  - `EVP_MD_CTX_set_flags`
  - `EVP_get_digestbynid`

Reasoning boundary:
- The BIO/UIO control helpers are mostly `partial` because the public replacement exists through `BSL_UIO_Ctrl` and `BSL_UIO_*Flags`, but not through the same OpenSSL BIO function or macro surface.
- `OPENSSL_strdup` stayed `partial` because openHiTLS only exposes generic duplication through `BSL_SAL_Dump`, not a dedicated string helper.
- `EVP_MD_CTX_init/create` and `EVP_VerifyInit_ex/Update` stayed `partial` because openHiTLS exposes the digest and verify building blocks, but not the same blank-ctx or integrated verify-state model.
