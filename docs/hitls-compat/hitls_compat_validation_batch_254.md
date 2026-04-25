# openHiTLS Compatibility Validation Batch 254

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `PEM_*`, `PKCS5_*`, and `PKCS8_*` low-volume utility families lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes three low-volume but related helper families here:
  - generic PEM helpers:
    - `PEM_read`
    - `PEM_write`
    - `PEM_ASN1_read*`
    - `PEM_ASN1_write*`
    - `PEM_do_header`
    - `PEM_get_EVP_CIPHER_INFO`
    - `PEM_X509_INFO_*`
  - PKCS5 helper and wrapper functions:
    - `PKCS5_PBKDF2_HMAC*`
    - `PKCS5_PBE_*`
    - `PKCS5_pbe*`
    - `PKCS5_pbkdf2_set*`
  - PKCS8 helper and wrapper functions:
    - `PKCS8_encrypt*`
    - `PKCS8_decrypt*`
    - `PKCS8_PRIV_KEY_INFO_*`
    - `PKCS8_pkey_*`
    - `PKCS8_add_keyusage`
    - `PKCS8_set0_pbe*`
- openHiTLS public installed surface exposes two adjacent capabilities:
  - public PKCS8 key encode/decode:
    - `CRYPT_EAL_DecodeBuffKey`
    - `CRYPT_EAL_ProviderDecodeBuffKey`
    - `CRYPT_EAL_EncodeBuffKey`
    - `CRYPT_EAL_ProviderEncodeBuffKey`
    - with public types:
      - `PRIKEY_PKCS8_UNENCRYPT`
      - `PRIKEY_PKCS8_ENCRYPT`
  - public PBKDF2:
    - `CRYPT_PBKDF2_NewCtx`
    - `CRYPT_PBKDF2_SetParam`
    - `CRYPT_PBKDF2_Derive`
- openHiTLS also has adjacent public PEM-capable cert/crl/key encode/decode on installed APIs:
  - `HITLS_X509_CertParseBuff`
  - `HITLS_X509_CertGenBuff`
  - `HITLS_X509_CrlParseBuff`
  - `HITLS_X509_CrlGenBuff`
  - `CRYPT_EAL_EncodeBuffKey` with `BSL_FORMAT_PEM`
  - `CRYPT_EAL_DecodeBuffKey` with `BSL_FORMAT_PEM`
- openHiTLS does not expose a public generic PEM subsystem header or wrapper-object API for:
  - generic `PEM_*`
  - `X509_INFO`
  - `PKCS8_PRIV_KEY_INFO`
  - `X509_SIG`
  - `X509_ALGOR`

Verdict:
- keep `available = 0`
- adjust to `partial = 7`
- adjust to `not_available = 50`

Reasoning boundary:
- `partial` is justified only where openHiTLS has a practical public replacement path:
  - PBKDF2 helpers:
    - `PKCS5_PBKDF2_HMAC`
    - `PKCS5_PBKDF2_HMAC_SHA1`
  - PKCS8 encode/decode:
    - `PKCS8_encrypt`
    - `PKCS8_encrypt_ex`
    - `PKCS8_decrypt`
    - `PKCS8_decrypt_ex`
  - aggregate PEM writer:
    - `PEM_X509_INFO_write_bio`
- These remain `partial` because:
  - PBKDF2 replacement is a ctx pipeline, not the OpenSSL one-shot helper contract
  - PKCS8 replacement works through encoded buffers and `CRYPT_EAL_PkeyCtx`, not `PKCS8_PRIV_KEY_INFO *` / `X509_SIG *` wrapper objects
  - `PEM_X509_INFO_write_bio` is only compositionally replaceable by encoding cert/crl/key pieces separately; openHiTLS has no `X509_INFO` aggregate object or `BIO` contract
- `not_available` remains correct for the rest because openHiTLS public APIs do not provide a practical public replacement path for:
  - generic PEM helpers:
    - `PEM_ASN1_read*`
    - `PEM_ASN1_write*`
    - `PEM_read`
    - `PEM_write`
    - `PEM_bytes_read_bio*`
    - `PEM_def_callback`
    - `PEM_dek_info`
    - `PEM_do_header`
    - `PEM_get_EVP_CIPHER_INFO`
    - `PEM_proc_type`
    - `PEM_Sign*`
  - mixed PEM aggregate readers:
    - `PEM_X509_INFO_read*`
  - PKCS5 wrapper/object helpers:
    - `PKCS5_PBE_*`
    - `PKCS5_pbe*`
    - `PKCS5_pbkdf2_set*`
    - `PKCS5_pbe2_set*`
    - `PKCS5_v2_*`
  - PKCS8 wrapper/object helpers:
    - `PKCS8_PRIV_KEY_INFO_*`
    - `PKCS8_add_keyusage`
    - `PKCS8_get_attr`
    - `PKCS8_pkey_add1_attr*`
    - `PKCS8_pkey_get0`
    - `PKCS8_pkey_get0_attrs`
    - `PKCS8_pkey_set0`
    - `PKCS8_set0_pbe*`

Important boundary calls:
- `PEM_X509_INFO_read*` stays `not_available`
  - OpenSSL parses a mixed PEM stream into `STACK_OF(X509_INFO)`
  - openHiTLS public APIs parse cert/crl/key objects separately
  - there is no public mixed PEM iterator or `X509_INFO` wrapper model
- `PKCS8_encrypt/decrypt*` is `partial`
  - openHiTLS publicly supports PKCS8 encrypted/unencrypted key encode/decode
  - but only through encoded buffers and `CRYPT_EAL_PkeyCtx`
- `PEM_X509_INFO_write_bio` is `partial`
  - openHiTLS can publicly emit PEM cert/crl/key material
  - but not through a single `X509_INFO` aggregate writer

Representative evidence:
- OpenSSL declarations and docs:
  - [PEM_read.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PEM_read.pod#L13)
  - [PEM_read.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PEM_read.pod#L76)
  - [PEM_X509_INFO_read_bio_ex.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PEM_X509_INFO_read_bio_ex.pod#L12)
  - [PEM_X509_INFO_read_bio_ex.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PEM_X509_INFO_read_bio_ex.pod#L41)
  - [PKCS5_PBKDF2_HMAC.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PKCS5_PBKDF2_HMAC.pod#L11)
  - [PKCS8_encrypt.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PKCS8_encrypt.pod#L12)
  - [PKCS8_encrypt.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PKCS8_encrypt.pod#L32)
  - [PKCS8_pkey_add1_attr.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PKCS8_pkey_add1_attr.pod#L12)
- OpenSSL implementation evidence:
  - [pem_info.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_info.c#L29)
  - [pem_info.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_info.c#L224)
  - [pem_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_lib.c#L111)
  - [pem_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_lib.c#L441)
  - [pem_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pem/pem_lib.c#L517)
  - [p12_p8e.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs12/p12_p8e.c#L16)
  - [p12_p8d.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs12/p12_p8d.c#L14)
  - [p12_attr.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/pkcs12/p12_attr.c#L32)
  - [p8_pkey.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/asn1/p8_pkey.c#L53)
- openHiTLS public declarations:
  - [crypt_pbkdf2.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/pbkdf2/include/crypt_pbkdf2.h#L39)
  - [crypt_pbkdf2.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/pbkdf2/include/crypt_pbkdf2.h#L63)
  - [crypt_pbkdf2.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/pbkdf2/include/crypt_pbkdf2.h#L76)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L217)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L311)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L128)
  - [hitls_pki_cert.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_cert.h#L283)
  - [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L81)
  - [hitls_pki_crl.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/pki/hitls_pki_crl.h#L150)
- openHiTLS implementation evidence:
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L418)
  - [crypt_codecskey.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/codecskey/src/crypt_codecskey.c#L603)
  - [hitls_x509_cert.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_cert/src/hitls_x509_cert.c#L1059)
  - [hitls_x509_crl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/pki/x509_crl/src/hitls_x509_crl.c#L742)

Batch 254 inventory:
- total interfaces: `57`
- `partial = 7`
- `not_available = 50`
