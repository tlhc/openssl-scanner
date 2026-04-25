# openHiTLS Compatibility Validation Batch 257

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `CMAC_*`, `HMAC_*`, `ECDSA_*`, `ECDH_*`, `BUF_*`, `TXT_DB_*`, `MD4_*`, `MDC2_*`, `RIPEMD160_*`, `RC4_*`, and `PKCS1_MGF1` helper tails lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes several low-level helper families here:
  - CMAC/HMAC context helpers
  - low-level ECDSA/ECDH helpers
  - legacy one-shot digest helpers
  - legacy buffer/database helpers
  - legacy RC4 and PKCS1 mask-generation helpers
- openHiTLS public installed surface only exposes three adjacent families:
  - generic MAC contexts in [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L57)
  - generic pkey sign/verify/share-key APIs in [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L402)
  - generic digest APIs in [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L48)
- The real public boundary is narrower than the old coarse partial set:
  - `CRYPT_EAL_MacCopyCtx` and `CRYPT_EAL_MacReinit` are public, so `CMAC_CTX_copy`, `CMAC_resume`, and `HMAC_CTX_copy/reset` can stay `partial`
  - there is no public accessor for the internal cipher ctx behind CMAC
  - there is no public digest getter for a MAC ctx
  - documented `CRYPT_EAL_MacCtrl` parameters are GMAC-specific, so OpenSSL HMAC flag propagation has no public peer
  - `CRYPT_MD_AlgId` omits `MD4`, `MDC2`, and `RIPEMD160`

Verdict:
- adjust to `available = 1`
- adjust to `partial = 15`
- adjust to `not_available = 45`

Reasoning boundary:
- `available` is justified for only one direct lifecycle release API:
  - `CMAC_CTX_free`
    - `CRYPT_EAL_MacFreeCtx`
- `partial` is justified where openHiTLS has a practical public replacement path but the object model still differs:
  - `CMAC_CTX_cleanup`
    - `CRYPT_EAL_MacDeinit`
  - `CMAC_CTX_copy`
    - `CRYPT_EAL_MacCopyCtx`
  - `CMAC_CTX_new`
    - `CRYPT_EAL_MacNewCtx(CRYPT_MAC_CMAC_AES128 / AES192 / AES256 / SM4)`
  - `CMAC_Init`
    - `CRYPT_EAL_MacInit`
  - `CMAC_Update`
    - `CRYPT_EAL_MacUpdate`
  - `CMAC_Final`
    - `CRYPT_EAL_MacFinal`
  - `CMAC_resume`
    - `CRYPT_EAL_MacReinit`
  - `HMAC_CTX_copy`
    - `CRYPT_EAL_MacCopyCtx`
  - `HMAC_CTX_reset`
    - `CRYPT_EAL_MacDeinit`
    - `CRYPT_EAL_MacReinit`
  - `HMAC_Init`
    - `CRYPT_EAL_MacInit`
  - `HMAC_size`
    - `CRYPT_EAL_GetMacLen`
  - `ECDH_compute_key`
    - `CRYPT_EAL_PkeyComputeShareKey`
  - `ECDSA_sign`
    - `CRYPT_EAL_PkeySignData`
  - `ECDSA_verify`
    - `CRYPT_EAL_PkeyVerifyData`
  - `ECDSA_size`
    - `CRYPT_EAL_PkeyGetSignLen`
- These stay `partial` because:
  - CMAC/HMAC map onto generic `CRYPT_EAL_MacCtx` rather than OpenSSL typed helper structs
  - CMAC/HMAC algorithm selection is fixed at ctx creation time
  - ECDH/ECDSA map onto generic `CRYPT_EAL_PkeyCtx` instead of `EC_KEY *` and `EC_POINT *`
- `not_available` remains correct for the rest because openHiTLS public APIs do not provide a practical public replacement path for:
  - `CMAC_CTX_get0_cipher_ctx`
  - `HMAC_CTX_get_md`
  - `HMAC_CTX_set_flags`
  - all `ECDSA_SIG_*`
  - `ECDSA_do_*`
  - `ECDSA_sign_ex`
  - `ECDSA_sign_setup`
  - `ECDH_KDF_X9_62`
  - all `BUF_*`
  - all `TXT_DB_*`
  - `PKCS1_MGF1`
  - all `RC4_*`
  - `MD4`
  - `MDC2`
  - `RIPEMD160`
  - the corresponding low-level `*_Init/*_Update/*_Final/*_Transform` tails

Important boundary calls:
- `CMAC_CTX_get0_cipher_ctx` stays `not_available`
  - OpenSSL exposes the internal `EVP_CIPHER_CTX *` in [cmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cmac.h#L35)
  - openHiTLS public MAC API does not expose an internal cipher ctx accessor in [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L57)
- `HMAC_CTX_set_flags` stays `not_available`
  - OpenSSL applies flags to internal `EVP_MD_CTX` objects in [HMAC.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/HMAC.pod#L118)
  - openHiTLS documents only GMAC-oriented `MacCtrl` parameters in [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L186)
- `MD4`, `MDC2`, and `RIPEMD160` stay `not_available`
  - OpenSSL still exposes one-shot helpers in [md4.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/md4.h#L53), [mdc2.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/mdc2.h#L46), and [ripemd.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ripemd.h#L49)
  - openHiTLS public digest IDs in [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L68) stop at `MD5`, `SHA*`, `SHAKE*`, and `SM3`

Representative evidence:
- OpenSSL declarations and docs:
  - [cmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/cmac.h#L35)
  - [CMAC_CTX.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/CMAC_CTX.pod#L65)
  - [hmac.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/hmac.h#L50)
  - [HMAC.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/HMAC.pod#L118)
  - [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L1296)
  - [ECDSA_sign.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/ECDSA_sign.pod#L75)
  - [buffer.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/buffer.h#L51)
  - [txt_db.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/txt_db.h#L50)
  - [rsa.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rsa.h#L389)
  - [rc4.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/rc4.h#L35)
- openHiTLS public declarations:
  - [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L57)
  - [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L161)
  - [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L173)
  - [crypt_eal_mac.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_mac.h#L228)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L402)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L420)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L537)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L582)
  - [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L196)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L68)

Batch 257 inventory:
- total interfaces: `61`
- `available = 1`
- `partial = 15`
- `not_available = 45`
