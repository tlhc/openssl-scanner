# openHiTLS Compatibility Validation Batch 258

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining ASN.1/X509 wrapper tails lacking `analysis_doc`, including:
  - `ECPARAMETERS_*`
  - `ECPKPARAMETERS_*`
  - `RSAPrivateKey_*`
  - `RSAPublicKey_*`
  - `SCRYPT_PARAMS_*`
  - `PBE2PARAM_*`
  - `PBEPARAM_*`
  - `PBKDF2PARAM_*`
  - `PBMAC1PARAM_*`
  - `PBMAC1_get1_pbkdf2_param`
  - `DIRECTORYSTRING_*`
  - `DISPLAYTEXT_*`
  - `EDIPARTYNAME_*`
  - `OTHERNAME_*`
  - `EXTENDED_KEY_USAGE_*`
  - `ISSUER_SIGN_TOOL_*`
  - `PKEY_USAGE_PERIOD_*`
  - `TLS_FEATURE_*`
  - `BIGNUM_it`
  - `CBIGNUM_it`
  - `INT32_it`
  - `INT64_it`
  - `LONG_it`
  - `UINT32_it`
  - `UINT64_it`
  - `ZINT32_it`
  - `ZINT64_it`
  - `ZLONG_it`
  - `ZUINT32_it`
  - `ZUINT64_it`
  - `a2d_/a2i_/i2a_/i2s_/i2t_/i2v_/s2i_/v2i_` ASN.1 helpers

Status:
- completed

Initial evidence:
- OpenSSL exposes a large standalone wrapper/object/helper surface here:
  - ASN.1 allocation helpers from `DECLARE_ASN1_ALLOC_FUNCTIONS`
  - ASN.1 item exports from `DECLARE_ASN1_ITEM`
  - low-level wrapper duplication helpers like `RSAPrivateKey_dup`
  - PKCS5/PKCS8 parameter wrapper objects such as `PBE2PARAM`, `PBKDF2PARAM`, and `SCRYPT_PARAMS`
- openHiTLS public installed surface around this area is materially different:
  - generic key codecs:
    - `CRYPT_EAL_DecodeBuffKey`
    - `CRYPT_EAL_EncodeBuffKey`
  - generic decoder pipeline:
    - `CRYPT_DECODE_ProviderNewCtx`
    - `CRYPT_DECODE_Decode`
  - generic KDF runtime pipeline:
    - `CRYPT_EAL_KdfNewCtx`
    - `CRYPT_EAL_KdfSetParam`
    - `CRYPT_EAL_KdfDerive`
  - generic pkey duplication:
    - `CRYPT_EAL_PkeyDupCtx`
- The key boundary is object-model mismatch:
  - OpenSSL exports standalone ASN.1 wrapper/object families
  - openHiTLS exports generic codecs, KDF contexts, and pkey contexts
  - practical replaceability exists only for the two RSA dup helpers

Verdict:
- keep `available = 0`
- adjust to `partial = 2`
- adjust to `not_available = 102`

Reasoning boundary:
- `partial` is justified only where openHiTLS has a practical public duplication path for the underlying key material:
  - `RSAPrivateKey_dup`
    - `CRYPT_EAL_PkeyDupCtx`
  - `RSAPublicKey_dup`
    - `CRYPT_EAL_PkeyDupCtx`
- These stay `partial` because:
  - OpenSSL duplicates low-level RSA wrapper objects
  - openHiTLS duplicates generic pkey contexts
  - the duplicated data can still serve the same migration need, but the public contract is not object-for-object
- `not_available` remains correct for the rest because openHiTLS public APIs do not provide a practically replaceable standalone wrapper/object path for:
  - all `*_new`
  - all `*_free`
  - all `*_it`
  - all ASN.1 string/object conversion helpers
  - `PBMAC1_get1_pbkdf2_param`
  - `OTHERNAME_cmp`
  - `ECPARAMETERS_*`
  - `ECPKPARAMETERS_*`
  - `SCRYPT_PARAMS_*`
  - all PKCS5/8 parameter wrapper families

Important boundary calls:
- `ECPARAMETERS_*` and `ECPKPARAMETERS_*` stay `not_available`
  - OpenSSL exposes standalone ASN.1 wrapper objects in [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L896)
  - openHiTLS public codecs in [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184) operate on key buffers and `CRYPT_EAL_PkeyCtx`, not `ECPARAMETERS` wrapper objects
- `SCRYPT_PARAMS_*` stays `not_available`
  - OpenSSL exposes standalone ASN.1 wrapper objects in [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L272)
  - openHiTLS public SCRYPT support is a runtime KDF context in [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L69)
- `RSAPrivateKey_it` and `RSAPublicKey_it` stay `not_available`
  - OpenSSL exports ASN.1 item globals through its ASN.1 templates in [X509_dup.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/X509_dup.pod#L470)
  - openHiTLS public headers do not expose ASN1_ITEM-style contracts for low-level RSA wrapper objects

Representative evidence:
- OpenSSL declarations and docs:
  - [X509_dup.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/X509_dup.pod#L470)
  - [EC_GROUP_new.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/EC_GROUP_new.pod#L38)
  - [PBMAC1_get1_pbkdf2_param.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/PBMAC1_get1_pbkdf2_param.pod#L12)
  - [x509.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/x509.h.in#L1004)
  - [asn1t.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/asn1t.h.in#L877)
  - [ec.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ec.h#L896)
- openHiTLS public declarations:
  - [crypt_eal_pkey.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_pkey.h#L172)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184)
  - [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281)
  - [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L69)
  - [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L81)
  - [crypt_eal_kdf.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_kdf.h#L94)

Batch 258 inventory:
- total interfaces: `104`
- `partial = 2`
- `not_available = 102`
