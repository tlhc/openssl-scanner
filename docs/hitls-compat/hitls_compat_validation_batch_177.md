# openHiTLS Compatibility Validation Batch 177

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_ENCODER_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a fetched encoder descriptor and encoder-context family in [encoder.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/encoder.h#L29), [encoder.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/encoder.h#L50), [encoder.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/encoder.h#L83), and [encoder.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/encoder.h#L105).
- openHiTLS public installed headers expose encode functionality through a different public surface in [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L281), [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L311), and [crypt_eal_codecs.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_codecs.h#L327).
- That surface provides encode capability, but not the OpenSSL fetched descriptor / instance / ctx object model.

Verdict:
- all `38` interfaces in this batch remain `not_available`

Reasoning boundary:
- Public encode capability alone is not enough to classify OpenSSL `OSSL_ENCODER_*` descriptor/ctx APIs as `partial`.
- openHiTLS does not expose a practical public analogue for the encoder descriptor / instance / ctx object model itself.
