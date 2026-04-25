# openHiTLS Compatibility Validation Batch 255

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `ENGINE_*`, `RAND_*`, `COMP_*`, and `DSO_*` utility families lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes four legacy utility/runtime subsystems here:
  - `ENGINE_*`
  - `RAND_*`
  - `COMP_*`
  - `DSO_*`
- openHiTLS public installed tree exposes:
  - a public random-number API:
    - `CRYPT_EAL_Randbytes`
    - `CRYPT_EAL_SetRandCallBack`
    - `CRYPT_EAL_SetRandCallBackEx`
    - `CRYPT_EAL_RandInit`
    - `CRYPT_EAL_ProviderRandInitCtx`
    - `CRYPT_EAL_DrbgNew`
  - no public installed subsystem for:
    - `ENGINE`
    - `DSO`
    - `COMP`
- openHiTLS public headers do not expose:
  - an `ENGINE` object family
  - a `DSO` object family
  - a compression method/context API
  - a getter for the current RNG callback/method
  - public/private/current DRBG accessors analogous to OpenSSL `RAND_get0_*`

Verdict:
- keep `available = 0`
- adjust to `partial = 4`
- adjust to `not_available = 64`

Reasoning boundary:
- `partial` is justified only where openHiTLS has a practical public replacement path:
  - `RAND_pseudo_bytes`
    - `CRYPT_EAL_Randbytes`
  - `RAND_set_rand_method`
    - `CRYPT_EAL_SetRandCallBack`
    - `CRYPT_EAL_SetRandCallBackEx`
  - `RAND_set_DRBG_type`
    - `CRYPT_EAL_RandInit`
    - `CRYPT_EAL_ProviderRandInitCtx`
    - `CRYPT_EAL_DrbgNew`
  - `RAND_set_seed_source_type`
    - `CRYPT_EAL_RandInit(seedMeth, seedCtx)`
    - `CRYPT_EAL_ProviderRandInitCtx`
- These remain `partial` because:
  - OpenSSL uses `RAND_METHOD` and string/property-based DRBG selection
  - openHiTLS uses callback setters and init-time algorithm/seed-method selection
  - the object model and runtime control surface are different
- `not_available` remains correct for the rest because openHiTLS public APIs do not provide a practical public replacement path for:
  - all `ENGINE_*`
  - all `DSO_*`
  - all `COMP_*`
  - `RAND_OpenSSL`
  - `RAND_get_rand_method`
  - `RAND_file_name`
  - `RAND_load_file`
  - `RAND_write_file`
  - `RAND_get0_primary`
  - `RAND_get0_public`
  - `RAND_get0_private`
  - `RAND_set0_public`
  - `RAND_set0_private`
  - `RAND_keep_random_devices_open`

Important boundary calls:
- `RAND_get_rand_method` stays `not_available`
  - openHiTLS has public callback setters
  - there is no public getter for the current RNG method/callback
- `RAND_set_rand_engine` stays `not_available`
  - openHiTLS has no `ENGINE` public subsystem
- all `COMP_*` stay `not_available`
  - openHiTLS public installed tree exposes no compression method/context subsystem

Representative evidence:
- OpenSSL declarations and docs:
  - [rand.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/rand.h#L49)
  - [rand.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/rand.h#L60)
  - [rand.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/rand.h#L78)
  - [rand.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/rand.h#L81)
  - [rand.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/rand.h#L87)
  - [rand.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/rand.h#L99)
  - [engine.h](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/engine.h#L1175)
  - [comp.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/comp.h.in#L35)
  - [RAND_set_rand_method.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/RAND_set_rand_method.pod#L15)
  - [RAND_set_rand_method.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/RAND_set_rand_method.pod#L30)
  - [RAND_set_DRBG_type.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/RAND_set_DRBG_type.pod#L13)
  - [RAND_bytes.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/RAND_bytes.pod#L12)
  - [RAND_add.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/RAND_add.pod#L16)
  - [RAND_load_file.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/RAND_load_file.pod#L11)
  - [ENGINE_add.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/ENGINE_add.pod#L58)
  - [SSL_COMP_add_compression_method.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/SSL_COMP_add_compression_method.pod#L13)
- openHiTLS public declarations:
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L44)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L54)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L66)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L76)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L107)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L124)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L190)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L204)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L273)
  - [crypt_eal_rand.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_rand.h#L287)

Batch 255 inventory:
- total interfaces: `68`
- `partial = 4`
- `not_available = 64`
