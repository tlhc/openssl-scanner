# openHiTLS Compatibility Validation Batch 211

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `ASYNC_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a full async subsystem across `include/openssl/async.h` and `crypto/async/*`, including:
  - `ASYNC_start_job`
  - `ASYNC_pause_job`
  - `ASYNC_init_thread`
  - `ASYNC_cleanup_thread`
  - `ASYNC_get_current_job`
  - `ASYNC_get_wait_ctx`
  - `ASYNC_WAIT_CTX_*`
- openHiTLS public installed headers expose no async job subsystem and no wait-context object family.
- openHiTLS public tree has no job pool, pause/resume, or wait-fd callback subsystem analogous to OpenSSL async.

Verdict:
- keep `available = 0`
- keep `partial = 0`
- keep `not_available = 22`

Reasoning boundary:
- This batch is not blocked by one missing helper.
- The whole async subsystem is absent from the openHiTLS public surface.
- Since there is no practical public replacement path for jobs, wait contexts, callback registration, or memory hooks, the entire batch remains `not_available`.
