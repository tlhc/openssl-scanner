# openHiTLS Compatibility Validation Batch 163

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `OSSL_PARAM_*` entries lacking `analysis_doc`
- includes both `OSSL_PARAM_BLD_*` and plain `OSSL_PARAM_*`

Status:
- completed

Initial evidence:
- OpenSSL exposes the `OSSL_PARAM` object and builder family as a public parameter-transport surface used across provider-era APIs. The concrete implementation spans [params_dup.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/params_dup.c#L105), [param_build.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/param_build.c#L91), [params_from_text.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/params_from_text.c#L217), and wide in-tree usage of `OSSL_PARAM_construct_*`, `OSSL_PARAM_locate*`, `OSSL_PARAM_get_*`, and `OSSL_PARAM_set_*`.
- openHiTLS exposes a public parameter surface in [bsl_params.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_params.h#L30) with:
  - `BSL_PARAM_InitValue`
  - `BSL_PARAM_SetValue`
  - `BSL_PARAM_GetPtrValue`
  - `BSL_PARAM_GetValue`
  - `BSL_PARAM_FindConstParam`
  - `BSL_PARAM_FindParam`
  - `BSL_PARAM_Free`
  - `BSL_PARAM_MAKER_New`
  - `BSL_PARAM_MAKER_PushValue`
  - `BSL_PARAM_MAKER_DeepPushValue`
  - `BSL_PARAM_MAKER_ToParam`
  - `BSL_PARAM_MAKER_Free`
- openHiTLS also uses this public `BSL_Param` surface broadly in public-facing crypto and PKI APIs, including KDF, CMS, provider, and pkey import/export paths.

Verdict:
- all `76` interfaces in this batch remain `partial`

Reasoning boundary:
- The public replacement path is real:
  - plain param construction maps to `BSL_PARAM_InitValue`
  - mutation maps to `BSL_PARAM_SetValue`
  - lookup maps to `BSL_PARAM_FindParam` / `BSL_PARAM_FindConstParam`
  - typed get/set maps to `BSL_PARAM_GetValue` / `BSL_PARAM_GetPtrValue` / `BSL_PARAM_SetValue`
  - builder lifecycle maps to `BSL_PARAM_MAKER_*`
  - free maps to `BSL_PARAM_Free`
- But the object model is still materially different:
  - OpenSSL uses string-keyed `OSSL_PARAM`
  - openHiTLS uses integer-keyed `BSL_Param`
  - OpenSSL offers many typed constructor and builder helpers per scalar type
  - openHiTLS exposes a smaller generic init/push API with explicit `BSL_PARAM_VALUE_TYPE`
- Under the current practical-replaceability rule, that supports `partial`, not `available`.
