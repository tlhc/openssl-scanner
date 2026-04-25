# openHiTLS Compatibility Validation Batch 244

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `EVP` modern/core family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a mixed residual `EVP` surface here:
  - digest/XOF factories
  - one-shot digest/mac helpers
  - digest sign/verify helpers
  - Base64 helper/context APIs
  - PBE / scrypt / PKCS8 conversion helpers
  - default-properties and password-prompt helpers
- openHiTLS public installed tree exposes adjacent public surfaces for part of this set:
  - digest:
    - `CRYPT_EAL_MdNewCtx`
    - `CRYPT_EAL_MdInit`
    - `CRYPT_EAL_MdUpdate`
    - `CRYPT_EAL_MdFinal`
    - `CRYPT_EAL_MdSqueeze`
    - `CRYPT_EAL_Md`
  - MAC:
    - `CRYPT_EAL_MacNewCtx`
    - `CRYPT_EAL_MacInit`
    - `CRYPT_EAL_MacUpdate`
    - `CRYPT_EAL_MacFinal`
  - KDF:
    - `CRYPT_EAL_KdfNewCtx`
    - `CRYPT_EAL_KdfSetParam`
    - `CRYPT_EAL_KdfDerive`
    - `CRYPT_KDF_SCRYPT`
    - `CRYPT_SCRYPT_*`
  - Base64:
    - `BSL_BASE64_Decode`
  - one-shot pkey sign/verify:
    - `CRYPT_EAL_PkeySign`
    - `CRYPT_EAL_PkeyVerify`
- openHiTLS public installed tree still does not expose direct public equivalents for:
  - legacy digest factories such as `MD4`, `RIPEMD160`, `WHIRLPOOL`, `MDC2`, `BLAKE2`
  - `EVP_BytesToKey`
  - `EVP_ENCODE_CTX_copy/num`
  - `EVP_Open*` / `EVP_Seal*`
  - `EVP_PBE_*` registry helpers
  - `EVP_PKCS82PKEY*` / `EVP_PKEY2PKCS8`
  - password-prompt helpers
  - default-properties helpers

Verdict:
- keep `available = 0`
- adjust to `partial = 21`
- adjust to `not_available = 43`

Reasoning boundary:
- `partial` is justified where openHiTLS has a practical public replacement path:
  - `EVP_DecodeBlock`
  - `EVP_DigestFinalXOF`
  - `EVP_DigestInit_ex2`
  - `EVP_DigestSign`
  - `EVP_DigestSignInit_ex`
  - `EVP_DigestSqueeze`
  - `EVP_DigestVerify`
  - `EVP_DigestVerifyInit_ex`
  - `EVP_DigestVerifyUpdate`
  - `EVP_PBE_scrypt`
  - `EVP_PBE_scrypt_ex`
  - `EVP_Q_digest`
  - `EVP_Q_mac`
  - `EVP_sha224`
  - `EVP_sha3_224`
  - `EVP_sha3_256`
  - `EVP_sha3_384`
  - `EVP_sha3_512`
  - `EVP_shake128`
  - `EVP_shake256`
  - `EVP_sm3`
- These remain `partial` because:
  - openHiTLS uses algorithm IDs and ctx/one-shot APIs, not OpenSSL function-pointer factory contracts
  - `Q_digest/Q_mac` do not preserve the OpenSSL name/propq one-shot contract
  - `PBE_scrypt*` maps to public scrypt/KDF APIs with different parameter and object models
  - `DigestSign/DigestVerify` map to one-shot sign/verify only, without matching streaming phases
  - `DigestFinalXOF/DigestSqueeze` map to `MdFinal/MdSqueeze` with a different state model
- `not_available` remains correct for the rest because openHiTLS public APIs do not provide a practically substitutable path for those OpenSSL contracts.

Representative evidence:
- OpenSSL declarations:
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L643)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L651)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L653)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L672)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L755)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L823)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L875)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L877)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L881)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1178)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1456)
- OpenSSL implementation evidence:
  - [digest.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/digest.c#L341)
  - [digest.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/digest.c#L384)
  - [digest.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/digest.c#L565)
  - [mac_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/mac_lib.c#L254)
  - [pbe_scrypt.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/pbe_scrypt.c#L37)
  - [evp_key.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/evp_key.c#L80)
  - [p_sign.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/p_sign.c#L17)
  - [encode.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/encode.c#L340)
  - [encode.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/encode.c#L706)
- openHiTLS public declarations:
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L124)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L155)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L171)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L196)
  - [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L57)
  - [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L102)
  - [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L122)
  - [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L151)
  - [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L60)
  - [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L69)
  - [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L81)
  - [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L94)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L71)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L75)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L79)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L81)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L102)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L383)
  - [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L68)
  - [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L77)
  - [crypt_scrypt.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/scrypt/include/crypt_scrypt.h#L55)
  - [crypt_scrypt.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/scrypt/include/crypt_scrypt.h#L78)
  - [crypt_pbkdf2.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/pbkdf2/include/crypt_pbkdf2.h#L51)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L365)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L382)
- openHiTLS implementation/install-surface evidence:
  - [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L105)
  - [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L117)
  - [eal_md_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md_method.c#L121)
  - [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L174)
  - [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L220)
  - [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L249)
  - [eal_md.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_md.c#L322)
  - [eal_mac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_mac.c#L90)
  - [eal_mac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_mac.c#L115)
  - [eal_mac.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_mac.c#L162)
  - [eal_kdf_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_kdf_method.c#L64)
  - [eal_kdf_method.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/eal/src/eal_kdf_method.c#L73)
  - [bsl_base64.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_base64.h#L77)

Batch 244 inventory:
- total interfaces: `64`
- `partial = 21`
- `not_available = 43`
