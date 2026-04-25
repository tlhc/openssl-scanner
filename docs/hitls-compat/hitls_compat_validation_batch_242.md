# openHiTLS Compatibility Validation Batch 242

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining unsupported `EVP cipher factory` family lacking `analysis_doc`:
  - `EVP_aria_*`
  - `EVP_camellia_*`
  - `EVP_des_*`
  - `EVP_rc2_*`
  - `EVP_rc4*`
  - `EVP_bf_*`
  - `EVP_cast5_*`
  - `EVP_idea_*`
  - `EVP_seed_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes a broad legacy/alternate cipher factory surface in public `evp.h`, including:
  - `ARIA`
  - `CAMELLIA`
  - `DES/3DES`
  - `RC2/RC4`
  - `Blowfish`
  - `CAST5`
  - `IDEA`
  - `SEED`
- openHiTLS public installed cipher set is materially narrower.
- The installed cipher/provider listings in openHiTLS public-facing crypto IDs and provider tables show:
  - `AES`
  - `SM4`
  - `CHACHA20_POLY1305`
- No public installed IDs or provider registrations were found for:
  - `ARIA`
  - `CAMELLIA`
  - `DES/3DES`
  - `RC2/RC4`
  - `BF`
  - `CAST5`
  - `IDEA`
  - `SEED`

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 92`

Reasoning boundary:
- All `92` interfaces remain `not_available`.
- OpenSSL side here is a direct cipher-factory family returning `const EVP_CIPHER *` for specific algorithms and modes.
- openHiTLS does not expose matching public algorithm IDs or provider registrations for these cipher families.
- The absence is at the installed public algorithm layer, not just at the helper/wrapper layer.
- openHiTLS public cipher coverage in this area is centered on:
  - `AES`
  - `SM4`
  - `CHACHA20_POLY1305`
- Since the algorithm families themselves are not present in the public installed surface, there is no practical public replacement path for any of these `EVP_*` factories.

Representative evidence:
- OpenSSL declarations:
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L898)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L928)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L942)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L951)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L958)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1023)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1055)
  - [evp.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/evp.h#L1088)
- OpenSSL implementation evidence:
  - [e_aria.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/e_aria.c#L41)
  - [e_camellia.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/e_camellia.c#L21)
  - [e_des3.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/e_des3.c#L27)
  - [e_rc2.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/e_rc2.c#L34)
  - [e_rc4.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/e_rc4.c#L29)
  - [e_rc4_hmac_md5.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/e_rc4_hmac_md5.c#L26)
  - [c_allc.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/c_allc.c#L197)
  - [c_allc.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/evp/c_allc.c#L233)
- openHiTLS public/installed cipher evidence:
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L150)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L180)
  - [crypt_algid.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_algid.h#L183)
  - [cmvp_iso19790.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/cmvp/iso_prov/cmvp_iso19790.c#L417)
  - [cmvp_iso19790.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/cmvp/iso_prov/cmvp_iso19790.c#L425)
  - [cmvp_iso19790.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/cmvp/iso_prov/cmvp_iso19790.c#L426)
  - [crypt_iso_provider.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/cmvp/iso_prov/crypt_iso_provider.c#L151)
  - [crypt_iso_provider.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/cmvp/iso_prov/crypt_iso_provider.c#L168)
  - [crypt_iso_provider.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/cmvp/iso_prov/crypt_iso_provider.c#L170)

Batch 242 inventory:
- total interfaces: `92`
- `not_available = 92`
