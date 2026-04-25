# openHiTLS Compatibility Validation Batch 075

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `IDEA_cbc_encrypt`
- `IDEA_cfb64_encrypt`
- `IDEA_ecb_encrypt`
- `IDEA_encrypt`
- `IDEA_ofb64_encrypt`
- `IDEA_options`
- `IDEA_set_decrypt_key`
- `IDEA_set_encrypt_key`

Status:
- completed

Initial evidence:
- openHiTLS exposes no public IDEA cipher IDs in `CRYPT_CIPHER_AlgId`, no IDEA entries in default provider dispatch, and no IDEA entries in EAL cipher-method tables.
- The openHiTLS crypto tree also has no IDEA implementation directory under [crypto](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto).

## 1. `IDEA_cbc_encrypt`
- OpenSSL declaration/implementation: [idea.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/idea.h#L49), [i_cbc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/idea/i_cbc.c#L20)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L42)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public IDEA CBC family.

## 2. `IDEA_cfb64_encrypt`
- OpenSSL declaration/implementation: [idea.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/idea.h#L53), [i_cfb64.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/idea/i_cfb64.c#L26)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public IDEA CFB family.

## 3. `IDEA_ecb_encrypt`
- OpenSSL declaration/implementation: [idea.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/idea.h#L42), [i_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/idea/i_ecb.c#L26)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public IDEA ECB family.

## 4. `IDEA_encrypt`
- OpenSSL declaration/implementation: [idea.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/idea.h#L62), [i_cbc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/idea/i_cbc.c#L96)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public IDEA primitive or key-schedule surface.

## 5. `IDEA_ofb64_encrypt`
- OpenSSL declaration/implementation: [idea.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/idea.h#L58), [i_ofb64.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/idea/i_ofb64.c#L25)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public IDEA OFB family.

## 6. `IDEA_options`
- OpenSSL declaration/implementation: [idea.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/idea.h#L41), [i_ecb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/idea/i_ecb.c#L21)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public IDEA surface, so there is no IDEA implementation-options string.

## 7. `IDEA_set_decrypt_key`
- OpenSSL declaration/implementation: [idea.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/idea.h#L47), [i_skey.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/idea/i_skey.c#L61)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public IDEA key-schedule surface.

## 8. `IDEA_set_encrypt_key`
- OpenSSL declaration/implementation: [idea.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/idea.h#L45), [i_skey.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/idea/i_skey.c#L21)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public IDEA key-schedule surface.

## Batch 075 summary

Keep `not_available`:
- `IDEA_cbc_encrypt`
- `IDEA_cfb64_encrypt`
- `IDEA_ecb_encrypt`
- `IDEA_encrypt`
- `IDEA_ofb64_encrypt`
- `IDEA_options`
- `IDEA_set_decrypt_key`
- `IDEA_set_encrypt_key`

Main observation:
- IDEA is a fully absent legacy family in the public openHiTLS surface.
- There is no object-ID or cipher-dispatch evidence strong enough to upgrade any entry beyond `not_available`.
