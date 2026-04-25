# openHiTLS Compatibility Validation Batch 012

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_version`
- `SSL_get_state`
- `SSL_state_string`
- `SSL_get_quiet_shutdown`
- `SSL_get_shutdown`
- `SSL_get_num_tickets`
- `SSL_get_options`
- `SSL_clear_options`
- `SSL_has_pending`
- `SSL_is_init_finished`

Status:
- completed

Initial evidence:
- OpenSSL declarations are concentrated in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1582), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1653), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1654), [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2076), plus runtime implementations in [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1481), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1537), and [ssl_stat.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_stat.c#L1).
- openHiTLS public counterparts are concentrated in [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L728), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L749), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1246), [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1268), plus implementations in [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c) and [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L736).
- Current mapping baseline for this batch is mostly `partial`, but some getters may already be direct enough for `available`.

## 1. `SSL_version`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2057), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4300)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L325), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L29)
- Verdict: keep `partial`
- Why: openHiTLS returns status and writes the negotiated version through an out parameter.

## 2. `SSL_get_state`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2078), [statem.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/statem/statem.c#L71)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L739), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L591)
- Verdict: keep `partial`
- Why: openHiTLS again uses status + outparam.

## 3. `SSL_state_string`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1652), [ssl_stat.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_stat.c#L121)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L749), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L736)
- Verdict: change to `available`
- Why: both return a string for the current handshake state; the only difference is that openHiTLS expects the state value to be supplied explicitly.

## 4. `SSL_get_quiet_shutdown`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2054), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4285)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1001), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L216)
- Verdict: keep `partial`
- Why: same boolean information, but returned through status + outparam.

## 5. `SSL_get_shutdown`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2056), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4295)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L314), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L262)
- Verdict: keep `partial`
- Why: same state information, but openHiTLS uses status + outparam and a `uint32_t *`.

## 6. `SSL_get_num_tickets`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2221), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4762)
- openHiTLS declaration/implementation: [hitls_session.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_session.h#L112), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L547)
- Verdict: change to `available`
- Why: direct getter exists and returns the ticket count value directly.

## 7. `SSL_get_options`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L579), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4935)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1311), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L356)
- Verdict: keep `partial`
- Why: same concept, but openHiTLS uses status + outparam and a different bit vocabulary.

## 8. `SSL_clear_options`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L581), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L4955)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L1301), [conn_ctrl.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_ctrl.c#L348)
- Verdict: keep `partial`
- Why: same role, but return conventions and option vocabulary differ.

## 9. `SSL_has_pending`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1567), [ssl_lib.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_lib.c#L1549)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L453), [conn_read.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_read.c#L526)
- Verdict: keep `partial`
- Why: same semantic question, but openHiTLS uses status + outparam.

## 10. `SSL_is_init_finished`
- Current JSON: `partial`
- OpenSSL declaration/implementation: [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1076), [statem.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/statem/statem.c#L81)
- openHiTLS declaration/implementation: [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L430), [conn_establish.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/cm/src/conn_establish.c#L577)
- Verdict: keep `partial`
- Why: same boolean information, but openHiTLS returns status and writes the result through an out parameter.

## Batch 012 summary

Change to `available`:
- `SSL_state_string`
- `SSL_get_num_tickets`

Keep `partial`:
- `SSL_version`
- `SSL_get_state`
- `SSL_get_quiet_shutdown`
- `SSL_get_shutdown`
- `SSL_get_options`
- `SSL_clear_options`
- `SSL_has_pending`
- `SSL_is_init_finished`

Main observation:
- In this family, the main source of `partial` is not missing functionality but openHiTLS’s pervasive status-plus-outparam pattern.
