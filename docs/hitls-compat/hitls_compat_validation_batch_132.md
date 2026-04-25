# openHiTLS Compatibility Validation Batch 132

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SRP_Calc_A`
- `SRP_Calc_A_param`
- `SRP_Calc_B`
- `SRP_Calc_B_ex`
- `SRP_Calc_client_key`
- `SRP_Calc_client_key_ex`
- `SRP_Calc_server_key`
- `SRP_Calc_u`
- `SRP_Calc_u_ex`
- `SRP_Calc_x`
- `SRP_Calc_x_ex`
- `SRP_VBASE_add0_user`
- `SRP_VBASE_free`
- `SRP_VBASE_get1_by_user`
- `SRP_VBASE_get_by_user`
- `SRP_VBASE_init`
- `SRP_VBASE_new`
- `SRP_Verify_A_mod_N`
- `SRP_Verify_B_mod_N`
- `SRP_check_known_gN_param`
- `SRP_create_verifier`
- `SRP_create_verifier_BN`
- `SRP_create_verifier_BN_ex`
- `SRP_create_verifier_ex`
- `SRP_get_default_gN`
- `SRP_user_pwd_free`
- `SRP_user_pwd_new`
- `SRP_user_pwd_set0_sv`
- `SRP_user_pwd_set1_ids`
- `SRP_user_pwd_set_gN`

Status:
- completed

Initial evidence:
- OpenSSL exposes the full SRP public surface in [srp.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/srp.h.in#L69), [srp.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/srp.h.in#L105), [srp.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/srp.h.in#L163), and `SSL` glue in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L639).
- OpenSSL implements SRP math and verifier-db helpers in [srp_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/srp/srp_lib.c#L63) and [srp_vfy.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/srp/srp_vfy.c#L179).
- No public `SRP` or `srp` symbol was found anywhere in openHiTLS headers, crypto, tls, or pki trees.
- Under the current replaceability rule, absence of any public SRP surface means there is no practical substitution path for developers.

Verdict:
- keep `not_available` for all entries in scope.
