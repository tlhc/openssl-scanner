# openHiTLS Compatibility Validation Batch 159

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `EVP_PKEY_*` entries lacking `analysis_doc`
- excludes `EVP_PKEY_CTX_*`, which were already covered in earlier batches
- covers these subfamilies in one evidence model:
  - `EVP_PKEY_asn1_*`
  - `EVP_PKEY_meth_*`
  - `EVP_PKEY` operation helpers
  - `EVP_PKEY` getter/setter/import/export helpers
  - `EVP_PKEY` print/attr/type helper families

Status:
- completed

Initial evidence:
- OpenSSL exposes a broad `EVP_PKEY` object/helper surface in [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1258), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1271), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1306), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1767), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1801), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1812), [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1822), and [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1875).
- openHiTLS exposes a public generic pkey context surface in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L172), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L192), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L251), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L305), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L365), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L453), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L511), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L549), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L639), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L663), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L675), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L697), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L709), and [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L736).
- openHiTLS also exposes public key codec and provider entry points in [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L217), [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L311), and [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L71).
- But openHiTLS does not expose public installed descriptor families corresponding to OpenSSL's legacy/customizable `EVP_PKEY_ASN1_METHOD` and `EVP_PKEY_METHOD` registry surfaces, nor public per-key provider/name/description metadata helpers.

Verdict:
- adjust to `available`:
  - `EVP_PKEY_encapsulate_init`
  - `EVP_PKEY_encapsulate`
  - `EVP_PKEY_decapsulate_init`
  - `EVP_PKEY_decapsulate`
- keep or adjust to `partial`:
  - `54` interfaces in this batch
  - representative entries:
    - `EVP_PKEY_Q_keygen`
    - `EVP_PKEY_check`
    - `EVP_PKEY_cmp`
    - `EVP_PKEY_copy_parameters`
    - `EVP_PKEY_decrypt`
    - `EVP_PKEY_decrypt_init`
    - `EVP_PKEY_derive_init_ex`
    - `EVP_PKEY_derive_set_peer`
    - `EVP_PKEY_dup`
    - `EVP_PKEY_encrypt`
    - `EVP_PKEY_encrypt_init`
    - `EVP_PKEY_export`
    - `EVP_PKEY_fromdata`
    - `EVP_PKEY_fromdata_init`
    - `EVP_PKEY_generate`
    - `EVP_PKEY_get0_DH`
    - `EVP_PKEY_get0_DSA`
    - `EVP_PKEY_get0_EC_KEY`
    - `EVP_PKEY_get0_RSA`
    - `EVP_PKEY_get1_DH`
    - `EVP_PKEY_get1_DSA`
    - `EVP_PKEY_get1_EC_KEY`
    - `EVP_PKEY_get1_RSA`
    - `EVP_PKEY_get1_encoded_public_key`
    - `EVP_PKEY_get_base_id`
    - `EVP_PKEY_get_bits`
    - `EVP_PKEY_get_ec_point_conv_form`
    - `EVP_PKEY_get_ex_data`
    - `EVP_PKEY_get_group_name`
    - `EVP_PKEY_get_id`
    - `EVP_PKEY_get_security_bits`
    - `EVP_PKEY_get_size`
    - `EVP_PKEY_keygen`
    - `EVP_PKEY_keygen_init`
    - `EVP_PKEY_pairwise_check`
    - `EVP_PKEY_parameters_eq`
    - `EVP_PKEY_paramgen`
    - `EVP_PKEY_paramgen_init`
    - `EVP_PKEY_private_check`
    - `EVP_PKEY_set1_DH`
    - `EVP_PKEY_set1_DSA`
    - `EVP_PKEY_set1_EC_KEY`
    - `EVP_PKEY_set1_encoded_public_key`
    - `EVP_PKEY_set_ex_data`
    - `EVP_PKEY_sign`
    - `EVP_PKEY_sign_init`
    - `EVP_PKEY_sign_init_ex`
    - `EVP_PKEY_type`
    - `EVP_PKEY_up_ref`
    - `EVP_PKEY_verify_init_ex`
    - `EVP_PKEY_verify_recover`
    - `EVP_PKEY_verify_recover_init`
    - `EVP_PKEY_verify_recover_init_ex`
- keep `not_available`:
  - `141` interfaces in this batch
  - whole families that stay `not_available`:
    - all `EVP_PKEY_asn1_*`
    - all `EVP_PKEY_meth_*`
    - all `EVP_PKEY_*attr*`
    - all `EVP_PKEY_*print*`
    - per-key provider/name/description/engine metadata helpers
    - parameter-table and type-mutation helpers

Reasoning boundary:
- `available` was reserved for cases where openHiTLS exposes a direct public operation with a practical migration path on the pkey surface itself. The KEM helpers crossed that threshold because `CRYPT_EAL_PkeyEncapsInit`, `CRYPT_EAL_PkeyEncaps`, `CRYPT_EAL_PkeyDecapsInit`, and `CRYPT_EAL_PkeyDecaps` exist as public installed APIs.
- `partial` covers the large middle band where public openHiTLS functionality exists, but the API shape is still meaningfully different:
  - generic `CRYPT_EAL_PkeyCtx` instead of `EVP_PKEY` / `EVP_PKEY_CTX`
  - ctrl-dispatch or split import/export APIs instead of dedicated OpenSSL helpers
  - enum/id and typed-parameter semantics instead of OpenSSL NID/provider-metadata semantics
- `not_available` remains correct for the registry/descriptor/attribute/print families because openHiTLS does not expose those public object models at all. Internal method tables or provider plumbing were not counted as truth-library analogues.
