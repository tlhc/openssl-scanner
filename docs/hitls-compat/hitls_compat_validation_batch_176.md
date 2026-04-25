# openHiTLS Compatibility Validation Batch 176

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_DECODER_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a fetched decoder descriptor and decoder-context family in [decoder.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/decoder.h#L29), [decoder.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/decoder.h#L50), [decoder.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/decoder.h#L82), and [decoder.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/decoder.h#L112).
- openHiTLS public installed headers expose decode functionality through a different public surface in [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L35), [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L45), [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L137), [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L184), and [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L217).
- That surface provides decode capability, but not the OpenSSL fetched descriptor / instance / ctx object model.

Verdict:
- all `41` interfaces in this batch remain `not_available`

Reasoning boundary:
- Public decode capability alone is not enough to classify OpenSSL `OSSL_DECODER_*` descriptor/ctx APIs as `partial`.
- openHiTLS does not expose a practical public analogue for the decoder descriptor / instance / ctx object model itself.
