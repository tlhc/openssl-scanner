# openHiTLS Compatibility Validation Batch 184

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_PROVIDER_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes provider management APIs in `provider.h`.
- openHiTLS exposes public provider management in [crypt_eal_provider.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_provider.h#L54) and implementation in [crypt_provider.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/crypto/provider/src/mgr/crypt_provider.c#L195).

Verdict:
- `partial = 11`
- `not_available = 7`

Reasoning boundary:
- Runtime provider load/register/isloaded/unload/process/capability operations have a practical public analogue, but the handle and descriptor semantics differ from `OSSL_PROVIDER`.
- Metadata getters and helper surfaces without a public analogue remain `not_available`.
