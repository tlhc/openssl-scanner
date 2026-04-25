# openHiTLS Compatibility Validation Batch 253

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `CT_*`, `CTLOG_*`, and `SCT_*` family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a dedicated Certificate Transparency subsystem across:
  - log-store and log objects:
    - `CTLOG_STORE_*`
    - `CTLOG_*`
  - policy evaluation context:
    - `CT_POLICY_EVAL_CTX_*`
  - signed certificate timestamps:
    - `SCT_*`
    - `SCT_LIST_*`
- openHiTLS public installed headers under `include/`, `pki/`, `tls/`, and `crypto/` do not expose a corresponding Certificate Transparency subsystem.
- The repository has adjacent PKI and TLS public surfaces, but no public `CTLOG`, `CT_POLICY`, or `SCT` object family or helper API.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 54`

Reasoning boundary:
- OpenSSL here provides a complete public CT subsystem:
  - `CTLOG_STORE_new*`, `CTLOG_STORE_load_*`, `CTLOG_STORE_get0_log_by_id`
  - `CTLOG_new*`, `CTLOG_get0_*`
  - `CT_POLICY_EVAL_CTX_new*`, `CT_POLICY_EVAL_CTX_set*`, `CT_POLICY_EVAL_CTX_get*`
  - `SCT_new*`, `SCT_set*`, `SCT_get*`, `SCT_validate`, `SCT_LIST_validate`, `SCT_print`
- openHiTLS public installed surface has no practical replacement path for any of those contracts.
- This is a hard subsystem boundary, not a contract mismatch on top of an existing public capability.
- Therefore the whole batch remains `not_available`.

Representative evidence:
- OpenSSL CT policy docs:
  - [CT_POLICY_EVAL_CTX_new.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/CT_POLICY_EVAL_CTX_new.pod#L17)
  - [CT_POLICY_EVAL_CTX_new.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/CT_POLICY_EVAL_CTX_new.pod#L61)
- OpenSSL log-store and SCT docs:
  - [CTLOG_new.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/CTLOG_new.pod#L14)
  - [CTLOG_new.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/CTLOG_new.pod#L31)
  - [SCT_new.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/SCT_new.pod#L38)
  - [SCT_new.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/SCT_new.pod#L84)
  - [SCT_validate.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/SCT_validate.pod#L21)
  - [SCT_print.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/SCT_print.pod#L12)
- OpenSSL implementation evidence:
  - [ct_log.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ct/ct_log.c#L100)
  - [ct_log.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ct/ct_log.c#L256)
  - [ct_sct.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ct/ct_sct.c#L22)
  - [ct_prn.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ct/ct_prn.c#L70)
  - [ct_sct_ctx.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/ct/ct_sct_ctx.c#L23)

Batch 253 inventory:
- total interfaces: `54`
- `not_available = 54`
