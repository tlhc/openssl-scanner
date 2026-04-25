# openHiTLS Compatibility Validation Batch 148

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `EC_KEY_METHOD_free`
- `EC_KEY_METHOD_get_compute_key`
- `EC_KEY_METHOD_get_init`
- `EC_KEY_METHOD_get_keygen`
- `EC_KEY_METHOD_get_sign`
- `EC_KEY_METHOD_get_verify`
- `EC_KEY_METHOD_new`
- `EC_KEY_METHOD_set_compute_key`
- `EC_KEY_METHOD_set_init`
- `EC_KEY_METHOD_set_keygen`
- `EC_KEY_METHOD_set_sign`
- `EC_KEY_METHOD_set_verify`
- `EC_KEY_OpenSSL`
- `EC_KEY_can_sign`
- `EC_KEY_check_key`
- `EC_KEY_clear_flags`
- `EC_KEY_copy`
- `EC_KEY_decoded_from_explicit_params`
- `EC_KEY_get0_engine`
- `EC_KEY_get_conv_form`
- `EC_KEY_get_default_method`
- `EC_KEY_get_enc_flags`
- `EC_KEY_get_ex_data`
- `EC_KEY_get_flags`
- `EC_KEY_get_method`
- `EC_KEY_new_by_curve_name_ex`
- `EC_KEY_new_ex`
- `EC_KEY_new_method`
- `EC_KEY_oct2key`
- `EC_KEY_oct2priv`
- `EC_KEY_precompute_mult`
- `EC_KEY_print`
- `EC_KEY_print_fp`
- `EC_KEY_priv2buf`
- `EC_KEY_priv2oct`
- `EC_KEY_set_asn1_flag`
- `EC_KEY_set_conv_form`
- `EC_KEY_set_default_method`
- `EC_KEY_set_enc_flags`
- `EC_KEY_set_ex_data`
- `EC_KEY_set_flags`
- `EC_KEY_set_method`
- `EC_KEY_set_private_key`
- `EC_KEY_set_public_key`
- `EC_KEY_set_public_key_affine_coordinates`
- `EC_KEY_up_ref`

Status:
- completed

Initial evidence:
- OpenSSL exposes the low-level `EC_KEY` object model, method hooks, serialization helpers, and flag/query APIs in [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L980), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1029), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1041), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1085), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1096), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1108), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1146), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1158), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1179), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1273), and [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L1474).
- openHiTLS exposes the practical replacement surface through generic pkey contexts and ECC pkey helpers in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L160), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L172), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L228), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L251), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L266), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L293), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L320), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L347), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L649), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L675), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L686), and [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L697).
- openHiTLS exposes ECC-specific parameter, point-format, flag, and encoded public-key helpers in [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L118), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L688), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L699), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L705), [crypt_ecc_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc_pkey.h#L60), [crypt_ecc_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc_pkey.h#L175), [crypt_ecc_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc_pkey.h#L232), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L203), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L247), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L542), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L557), [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L633), and [eal_pkey_params.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_pkey_params.c#L67).
- openHiTLS does not expose any public `EC_KEY_METHOD` / `ENGINE` customization surface or public `EC_KEY` printing/precompute surface.

Verdict:
- keep `not_available`:
  - `EC_KEY_METHOD_free`
  - `EC_KEY_METHOD_get_compute_key`
  - `EC_KEY_METHOD_get_init`
  - `EC_KEY_METHOD_get_keygen`
  - `EC_KEY_METHOD_get_sign`
  - `EC_KEY_METHOD_get_verify`
  - `EC_KEY_METHOD_new`
  - `EC_KEY_METHOD_set_compute_key`
  - `EC_KEY_METHOD_set_init`
  - `EC_KEY_METHOD_set_keygen`
  - `EC_KEY_METHOD_set_sign`
  - `EC_KEY_METHOD_set_verify`
  - `EC_KEY_OpenSSL`
  - `EC_KEY_decoded_from_explicit_params`
  - `EC_KEY_get0_engine`
  - `EC_KEY_get_default_method`
  - `EC_KEY_get_method`
  - `EC_KEY_new_method`
  - `EC_KEY_precompute_mult`
  - `EC_KEY_print`
  - `EC_KEY_print_fp`
  - `EC_KEY_set_asn1_flag`
  - `EC_KEY_set_default_method`
  - `EC_KEY_set_method`
- adjust to `partial`:
  - `EC_KEY_can_sign`
  - `EC_KEY_check_key`
  - `EC_KEY_clear_flags`
  - `EC_KEY_copy`
  - `EC_KEY_get_conv_form`
  - `EC_KEY_get_enc_flags`
  - `EC_KEY_get_ex_data`
  - `EC_KEY_get_flags`
  - `EC_KEY_new_by_curve_name_ex`
  - `EC_KEY_new_ex`
  - `EC_KEY_oct2key`
  - `EC_KEY_oct2priv`
  - `EC_KEY_priv2buf`
  - `EC_KEY_priv2oct`
  - `EC_KEY_set_conv_form`
  - `EC_KEY_set_enc_flags`
  - `EC_KEY_set_ex_data`
  - `EC_KEY_set_flags`
  - `EC_KEY_set_private_key`
  - `EC_KEY_set_public_key`
  - `EC_KEY_set_public_key_affine_coordinates`
  - `EC_KEY_up_ref`

Reasoning boundary:
- Everything in the `EC_KEY_METHOD_*` / method / engine lane stayed `not_available` because openHiTLS has no public low-level EC method customization model.
- The lifecycle/import/export/flag/query lane reached `partial` because openHiTLS does provide public generic pkey and ECC helpers that cover substantial functionality, but only through the higher-level pkey context model, not OpenSSL's low-level `EC_KEY` object model.
