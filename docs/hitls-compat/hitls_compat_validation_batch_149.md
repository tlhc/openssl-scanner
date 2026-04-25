# openHiTLS Compatibility Validation Batch 149

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `EC_GROUP_check`
- `EC_GROUP_check_discriminant`
- `EC_GROUP_check_named_curve`
- `EC_GROUP_clear_free`
- `EC_GROUP_cmp`
- `EC_GROUP_copy`
- `EC_GROUP_dup`
- `EC_GROUP_get0_cofactor`
- `EC_GROUP_get0_field`
- `EC_GROUP_get0_generator`
- `EC_GROUP_get0_order`
- `EC_GROUP_get0_seed`
- `EC_GROUP_get_asn1_flag`
- `EC_GROUP_get_basis_type`
- `EC_GROUP_get_cofactor`
- `EC_GROUP_get_curve`
- `EC_GROUP_get_curve_GF2m`
- `EC_GROUP_get_curve_GFp`
- `EC_GROUP_get_degree`
- `EC_GROUP_get_ecparameters`
- `EC_GROUP_get_ecpkparameters`
- `EC_GROUP_get_field_type`
- `EC_GROUP_get_mont_data`
- `EC_GROUP_get_order`
- `EC_GROUP_get_pentanomial_basis`
- `EC_GROUP_get_point_conversion_form`
- `EC_GROUP_get_seed_len`
- `EC_GROUP_get_trinomial_basis`
- `EC_GROUP_have_precompute_mult`
- `EC_GROUP_method_of`
- `EC_GROUP_new`
- `EC_GROUP_new_by_curve_name_ex`
- `EC_GROUP_new_curve_GF2m`
- `EC_GROUP_new_curve_GFp`
- `EC_GROUP_new_from_ecparameters`
- `EC_GROUP_new_from_ecpkparameters`
- `EC_GROUP_new_from_params`
- `EC_GROUP_order_bits`
- `EC_GROUP_precompute_mult`
- `EC_GROUP_set_asn1_flag`
- `EC_GROUP_set_curve`
- `EC_GROUP_set_curve_GF2m`
- `EC_GROUP_set_curve_GFp`
- `EC_GROUP_set_curve_name`
- `EC_GROUP_set_generator`
- `EC_GROUP_set_point_conversion_form`
- `EC_GROUP_set_seed`
- `EC_GROUP_to_params`
- `EC_POINT_add`
- `EC_POINT_bn2point`
- `EC_POINT_clear_free`
- `EC_POINT_cmp`
- `EC_POINT_copy`
- `EC_POINT_dbl`
- `EC_POINT_dup`
- `EC_POINT_free`
- `EC_POINT_get_Jprojective_coordinates_GFp`
- `EC_POINT_get_affine_coordinates`
- `EC_POINT_get_affine_coordinates_GF2m`
- `EC_POINT_get_affine_coordinates_GFp`
- `EC_POINT_hex2point`
- `EC_POINT_invert`
- `EC_POINT_is_at_infinity`
- `EC_POINT_is_on_curve`
- `EC_POINT_make_affine`
- `EC_POINT_method_of`
- `EC_POINT_mul`
- `EC_POINT_oct2point`
- `EC_POINT_point2bn`
- `EC_POINT_point2buf`
- `EC_POINT_point2hex`
- `EC_POINT_set_Jprojective_coordinates_GFp`
- `EC_POINT_set_affine_coordinates`
- `EC_POINT_set_affine_coordinates_GF2m`
- `EC_POINT_set_affine_coordinates_GFp`
- `EC_POINT_set_compressed_coordinates`
- `EC_POINT_set_compressed_coordinates_GF2m`
- `EC_POINT_set_compressed_coordinates_GFp`
- `EC_POINT_set_to_infinity`

Status:
- completed

Initial evidence:
- OpenSSL exposes a full low-level `EC_GROUP` / `EC_POINT` object model in [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L174), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L221), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L324), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L571), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L646), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L760), and [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L815).
- openHiTLS does have internal ECC group/point machinery in [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L60), [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L101), [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L148), [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L204), and [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L236).
- But the public migration surface that scanner truth-library accepts remains the installed public include tree under [`openhitls-upstream/include`](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include), which only exposes generic pkey/EAL APIs and no public `EC_GROUP` / `EC_POINT` object family analogue.
- The nearest public APIs are pkey-level abstractions such as [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L172), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L192), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L216), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L239), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L251), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L305), and [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L596), which do not give developers a practical replacement path for OpenSSL's standalone low-level group/point object programming model.

Verdict:
- all 79 interfaces in this batch remain `not_available`

Reasoning boundary:
- Even though openHiTLS contains internal ECC group/point code, it does not expose a public `EC_GROUP` / `EC_POINT` family that developers can directly map or compositionally substitute in a practical migration.
- The public openHiTLS surface starts at the generic pkey/EAL layer, which is adequate for higher-level key operations but not for OpenSSL's low-level group arithmetic, point lifecycle, or group-parameter object programming style.
