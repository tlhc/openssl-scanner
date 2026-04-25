# openHiTLS Compatibility Validation Batch 070

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `AES_cfb128_encrypt`
- `AES_cfb1_encrypt`
- `AES_cfb8_encrypt`
- `AES_ofb128_encrypt`
- `AES_wrap_key`
- `AES_unwrap_key`
- `AES_ige_encrypt`
- `AES_bi_ige_encrypt`
- `AES_options`

Status:
- completed

Initial evidence:
- This batch closes the remaining `AES_*` legacy low-level APIs after Batch 068.
- The family splits cleanly into three buckets:
  - `CFB/OFB/WRAP`: public openHiTLS functionality exists through EAL cipher contexts, so these are `partial`.
  - `IGE/bi-IGE`: no public openHiTLS AES-IGE mode surface, so these stay `not_available`.
  - `AES_options`: OpenSSL exposes an AES-specific options string; openHiTLS only exposes generic cipher metadata queries.

## 1. `AES_cfb128_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L70), [aes_cfb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_cfb.c#L25)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L192), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L612), [test_suite_sdv_eal_aes.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c#L922)
- Verdict: change to `partial`
- Why: openHiTLS has public AES-CFB plus feedback-size control through `CRYPT_EAL_CipherCtrl`, but it does not expose OpenSSL's low-level `AES_KEY` plus `ivec/num` helper surface.

## 2. `AES_cfb1_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L74), [aes_cfb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_cfb.c#L35)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L192), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L612), [test_suite_sdv_eal_aes.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c#L922)
- Verdict: change to `partial`
- Why: openHiTLS public CFB mode can be configured down to 1-bit feedback, but the API shape is still a composed EAL flow rather than OpenSSL's direct helper.

## 3. `AES_cfb8_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L78), [aes_cfb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_cfb.c#L43)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L220), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L192), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L612), [test_suite_sdv_eal_aes.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c#L922)
- Verdict: change to `partial`
- Why: openHiTLS public CFB mode can be configured to 8-bit feedback, but it still lacks OpenSSL's low-level `AES_KEY` plus `ivec/num` helper contract.

## 4. `AES_ofb128_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L82), [aes_ofb.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_ofb.c#L19)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L195)
- Verdict: change to `partial`
- Why: openHiTLS exposes public AES-OFB via the EAL cipher surface, but not OpenSSL's low-level `AES_KEY` plus `ivec/num` helper signature.

## 5. `AES_wrap_key`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L97), [aes_wrap.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_wrap.c#L20)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L173), [test_suite_sdv_eal_aes_wrap.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes_wrap.c#L65)
- Verdict: change to `partial`
- Why: openHiTLS exposes public AES key-wrap through `CRYPT_CIPHER_AES*_WRAP_NOPAD`, but it does not expose OpenSSL's low-level `AES_KEY` helper API.

## 6. `AES_unwrap_key`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L101), [aes_wrap.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_wrap.c#L27)
- openHiTLS public declaration/implementation: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L57), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L102), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L166), [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L189), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L173), [test_suite_sdv_eal_aes_wrap.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes_wrap.c#L65)
- Verdict: change to `partial`
- Why: openHiTLS exposes public AES key-unwrap through `CRYPT_CIPHER_AES*_WRAP_NOPAD`, but it does not expose OpenSSL's low-level `AES_KEY` helper API.

## 7. `AES_ige_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L88), [aes_ige.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_ige.c#L48)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L197)
- Verdict: keep `not_available`
- Why: openHiTLS public AES mode IDs include CBC/CTR/ECB/XTS/CCM/GCM/WRAP/CFB/OFB, but not IGE.

## 8. `AES_bi_ige_encrypt`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L93), [aes_ige.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_ige.c#L186)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L197)
- Verdict: keep `not_available`
- Why: openHiTLS public AES mode IDs include CBC/CTR/ECB/XTS/CCM/GCM/WRAP/CFB/OFB, but not bi-IGE.

## 9. `AES_options`
- OpenSSL declaration/implementation: [aes.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/aes.h#L49), [aes_misc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/aes/aes_misc.c#L15)
- openHiTLS public declaration: [crypt_eal_cipher.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_cipher.h#L252)
- Verdict: keep `not_available`
- Why: openHiTLS exposes generic cipher metadata via `CRYPT_EAL_CipherGetInfo`, not an AES-specific implementation-options string.

## Batch 070 summary

Change to `partial`:
- `AES_cfb128_encrypt`
- `AES_cfb1_encrypt`
- `AES_cfb8_encrypt`
- `AES_ofb128_encrypt`
- `AES_wrap_key`
- `AES_unwrap_key`

Keep `not_available`:
- `AES_ige_encrypt`
- `AES_bi_ige_encrypt`
- `AES_options`

Main observation:
- Batch 068 already showed that openHiTLS has public AES functionality, but only through EAL cipher contexts.
- Batch 070 sharpens that conclusion:
  - `CFB/OFB/WRAP` are real public functional analogues, so they should not stay `not_available`.
  - `IGE/bi-IGE` and `AES_options` still have no public counterpart.
