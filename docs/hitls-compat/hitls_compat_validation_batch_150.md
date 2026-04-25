# openHiTLS Compatibility Validation Batch 150

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `EC_GF2m_simple_method`
- `EC_GFp_mont_method`
- `EC_GFp_nist_method`
- `EC_GFp_simple_method`
- `EC_METHOD_get_field_type`
- `EC_POINTs_make_affine`
- `EC_POINTs_mul`
- `EC_curve_nid2nist`
- `EC_curve_nist2nid`
- `EC_get_builtin_curves`

Status:
- completed

Initial evidence:
- OpenSSL exposes low-level method selectors, EC method queries, built-in curve registry, NIST name mapping, and multi-point helpers in [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L124), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L161), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L191), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L556), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L558), [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L865), and [ec.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/ec.h#L878).
- openHiTLS does contain internal ECC machinery and internal method tables in [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L60), [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L204), [crypt_ecc.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/include/crypt_ecc.h#L220), and [ecc_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_method.c#L39).
- openHiTLS also has an internal NIST-name mapping helper in [ecc_pkey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/ecc/src/ecc_pkey.c#L452), but it is not exposed through the installed public include tree.
- The public installed surface still begins at generic pkey/EAL APIs and TLS named-group enums in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L132), [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L649), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L702), [hitls_crypt_type.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_crypt_type.h#L207), and [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L857), which do not provide a direct or practically substitutable public analogue for this OpenSSL low-level family.

Verdict:
- all 10 interfaces in this batch remain `not_available`

Reasoning boundary:
- Internal ECC method tables, curve-name helpers, and point/group arithmetic do exist, but they are not exposed as the public installed API surface that this truth-library accepts.
- The nearest public surfaces are generic pkey/EAL and TLS named-group abstractions, which are too high-level and too differently shaped to serve as practical replacements for OpenSSL's low-level EC method registry, curve registry, or multi-point object APIs.
