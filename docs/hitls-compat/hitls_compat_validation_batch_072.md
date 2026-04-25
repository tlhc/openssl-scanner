# openHiTLS Compatibility Validation Batch 072

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `DES_is_weak_key`
- `DES_key_sched`
- `DES_ncbc_encrypt`
- `DES_ofb64_encrypt`
- `DES_options`
- `DES_pcbc_encrypt`
- `DES_quad_cksum`
- `DES_random_key`
- `DES_set_key`
- `DES_set_key_checked`
- `DES_string_to_2keys`
- `DES_string_to_key`
- `DES_xcbc_encrypt`

Status:
- completed

Initial evidence:
- Batch 071 already re-verified the public-surface fact pattern: no DES/3DES cipher IDs in `CRYPT_CIPHER_AlgId`, no DES/3DES cases in the public provider/EAL tables, and no `crypto/des` subtree in openHiTLS.
- This batch closes the remaining DES helpers built on top of that missing public DES surface.

## 1. `DES_is_weak_key`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L178), [set_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/set_key.c#L119)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614)
- Verdict: keep `not_available`
- Why: a DES weak-key helper without a public DES key surface would still be unusable, and openHiTLS does not expose that surface.

## 2. `DES_key_sched`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L188), [set_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/set_key.c#L391)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public DES key-schedule or DES algorithm family.

## 3. `DES_ncbc_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L93), [ncbc_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/ncbc_enc.c#L22)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: public tables expose no DES CBC family or DES ctx constructor.

## 4. `DES_ofb64_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L201), [ofb64enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/ofb64enc.c#L23)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_default_cipher.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/default/crypt_default_cipher.c#L145)
- Verdict: keep `not_available`
- Why: public tables expose no DES OFB family or DES ctx constructor.

## 5. `DES_options`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L76), [ecb_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/ecb_enc.c#L21)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS has no DES implementation-options string because it exposes no public DES surface.

## 6. `DES_pcbc_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L169), [pcbc_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/pcbc_enc.c#L18)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS has no public DES PCBC or DES primitive family.

## 7. `DES_quad_cksum`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L173), [qud_cksm.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/qud_cksm.c#L34)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: DES checksum helpers have no public analogue because DES itself is absent.

## 8. `DES_random_key`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L175), [rand_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/rand_key.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614)
- Verdict: keep `not_available`
- Why: DES key-generation helpers have no public analogue because openHiTLS exposes no public DES key family.

## 9. `DES_set_key`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L186), [set_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/set_key.c#L298)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public DES key-schedule surface.

## 10. `DES_set_key_checked`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L190), [set_key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/set_key.c#L315)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150), [crypt_types.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_types.h#L614)
- Verdict: keep `not_available`
- Why: openHiTLS exposes no public DES key-schedule surface; the DES control enum does not change that.

## 11. `DES_string_to_2keys`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L195), [str2key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/str2key.c#L46)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: string-to-DES-key helpers have no analogue because openHiTLS exposes no public DES key family.

## 12. `DES_string_to_key`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L193), [str2key.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/str2key.c#L19)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: string-to-DES-key helpers have no analogue because openHiTLS exposes no public DES key family.

## 13. `DES_xcbc_encrypt`
- OpenSSL declaration/implementation: [des.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/des.h#L97), [xcbc_enc.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/des/xcbc_enc.c#L20)
- openHiTLS evidence: [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
- Verdict: keep `not_available`
- Why: openHiTLS has no public DES XCBC or DES primitive family.

## Batch 072 summary

Keep `not_available`:
- `DES_is_weak_key`
- `DES_key_sched`
- `DES_ncbc_encrypt`
- `DES_ofb64_encrypt`
- `DES_options`
- `DES_pcbc_encrypt`
- `DES_quad_cksum`
- `DES_random_key`
- `DES_set_key`
- `DES_set_key_checked`
- `DES_string_to_2keys`
- `DES_string_to_key`
- `DES_xcbc_encrypt`

Main observation:
- This closes the remaining DES long tail.
- The conclusion stays the same across lifecycle, checksum, key-schedule, password-derived, and mode helpers: no public DES/3DES surface exists in openHiTLS.
