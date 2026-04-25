# openHiTLS Compatibility Validation Batch 185

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- all remaining `UI_method_*` entries lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes `UI_METHOD` callback registration/getter APIs in `crypto/ui/ui_lib.c`.
- openHiTLS exposes a narrower public UI method surface in [bsl_ui.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_ui.h#L244) and [bsl_ui.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_ui.h#L261).

Verdict:
- `partial = 8`
- `not_available = 9`

Reasoning boundary:
- The core `open/read/write/close` callback getters and setters have a practical public analogue.
- Flusher, prompt constructor, data duplicator/destructor, and ex-data helpers still lack a public analogue.
