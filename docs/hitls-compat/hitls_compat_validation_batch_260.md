# openHiTLS Compatibility Validation Batch 260

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining parameter/import-export/serialization tails lacking `analysis_doc`, including:
  - `DHparams_*`
  - `DSAparams_*`
  - `ECParameters_print*`
  - `ECPKParameters_print*`
  - `asn1_d2i_read_bio`
  - `b2i_*`
  - `i2b_*`
  - `i2o_ECPublicKey`
  - `o2i_ECPublicKey`
  - `i2o_SCT*`
  - `o2i_SCT*`

Status:
- completed

Initial evidence:
- OpenSSL exposes three different helper classes here:
  - standalone ASN.1 parameter dup/item/print helpers
  - BIO-based key import/export helpers
  - octet/TLS-wire serialization helpers
- openHiTLS public installed surface is narrower:
  - generic key duplication:
    - `CRYPT_EAL_PkeyDupCtx`
  - generic key import/export:
    - `CRYPT_EAL_PkeySetPub`
    - `CRYPT_EAL_PkeyGetPub`
  - generic key codecs:
    - `CRYPT_EAL_DecodeBuffKey`
    - `CRYPT_EAL_EncodeBuffKey`
  - generic key printing:
    - `CRYPT_EAL_PrintPubkey`
    - `CRYPT_EAL_PrintPrikey`
- That surface still leaves gaps:
  - no BIO abstraction
  - no CT subsystem
  - no parameter-only print API
  - no ASN1_ITEM-style `DHparams_it`

Verdict:
- keep `available = 0`
- adjust to `partial = 4`
- adjust to `not_available = 24`

Reasoning boundary:
- `partial` is justified only where openHiTLS has a practical public replacement path:
  - `DHparams_dup`
    - `CRYPT_EAL_PkeyDupCtx`
  - `DSAparams_dup`
    - `CRYPT_EAL_PkeyDupCtx`
  - `i2o_ECPublicKey`
    - `CRYPT_EAL_PkeyGetPub`
  - `o2i_ECPublicKey`
    - `CRYPT_EAL_PkeySetPub`
- These stay `partial` because:
  - OpenSSL uses low-level parameter or `EC_KEY *` helper contracts
  - openHiTLS uses generic pkey contexts and generic public-key containers
- `not_available` remains correct for:
  - `DHparams_it`
  - all `*_print*` parameter printers
  - `asn1_d2i_read_bio`
  - all `b2i_*`
  - all `i2b_*`
  - all `i2o_SCT*`
  - all `o2i_SCT*`

Important boundary calls:
- `DHparams_it` stays `not_available`
  - OpenSSL exposes an ASN.1 item in [dh.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/dh.h#L133)
  - openHiTLS public headers expose generic pkey duplication, not an ASN1_ITEM-style DHparams contract
- `DHparams_print*`, `DSAparams_print*`, `ECParameters_print*`, and `ECPKParameters_print*` stay `not_available`
  - OpenSSL documents parameter-only printers in [RSA_print.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/RSA_print.pod#L26) and [ECPKParameters_print.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/ECPKParameters_print.pod#L16)
  - openHiTLS public printing in [crypt_codecskey_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_print.c#L136) is limited to supported key objects and does not expose parameter-only printers
- `b2i_*` and `i2b_*` stay `not_available`
  - OpenSSL exposes BIO-based key blob helpers in [pem.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/pem.h#L520)
  - openHiTLS codecs in [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184) operate on buffer formats such as ASN1/PEM/PFX/PKCS12 rather than BIO+blob helpers
- `i2o_SCT*` and `o2i_SCT*` stay `not_available`
  - OpenSSL exposes CT TLS-wire helpers in [o2i_SCT_LIST.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/o2i_SCT_LIST.pod#L12)
  - openHiTLS public installed tree does not expose a CT public subsystem

Representative evidence:
- OpenSSL declarations and docs:
  - [dh.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/dh.h#L133)
  - [RSA_print.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/RSA_print.pod#L26)
  - [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L1236)
  - [pem.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/pem.h#L520)
  - [o2i_SCT_LIST.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/o2i_SCT_LIST.pod#L12)
- openHiTLS public declarations and implementations:
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L172)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L251)
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L305)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281)
  - [crypt_codecskey_print.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey_print.c#L136)

Batch 260 inventory:
- total interfaces: `28`
- `partial = 4`
- `not_available = 24`
