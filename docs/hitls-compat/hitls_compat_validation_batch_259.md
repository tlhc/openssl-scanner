# openHiTLS Compatibility Validation Batch 259

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `TLS_*`, `TLSv1_*`, `TLSv1_1_*`, `TLSv1_2_*`, `DTLS_*`, `DTLSv1_*`, and `DTLSv1_2_*` runtime/method tails lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes protocol selector helpers and DTLS runtime helpers here:
  - `TLS_method`
  - `TLSv1_2_method`
  - `DTLS_method`
  - `DTLSv1_2_method`
  - `DTLS_set_timer_cb`
  - `DTLS_get_data_mtu`
- openHiTLS public installed surface exposes config-constructor and endpoint/timer controls:
  - `HITLS_CFG_NewTLSConfig`
  - `HITLS_CFG_NewTLS12Config`
  - `HITLS_CFG_NewDTLSConfig`
  - `HITLS_CFG_NewDTLS12Config`
  - `HITLS_CFG_SetEndPoint`
  - `HITLS_SetEndPoint`
  - `HITLS_CFG_SetDtlsTimerCb`
  - `HITLS_SetDtlsTimerCb`
- The public boundary is straightforward:
  - TLS 1.2 and DTLS 1.2 constructors exist
  - TLS 1.0 / 1.1 and DTLS 1.0 constructors do not exist
  - there is no public DTLS data-MTU getter

Verdict:
- keep `available = 0`
- keep `partial = 11`
- keep `not_available = 11`

Reasoning boundary:
- `partial` is justified where openHiTLS has a practical public replacement path through config constructors or timer setters:
  - `TLS_method`
    - `HITLS_CFG_NewTLSConfig`
  - `TLSv1_2_client_method`
    - `HITLS_CFG_NewTLS12Config`
    - `HITLS_CFG_SetEndPoint`
  - `TLSv1_2_method`
    - `HITLS_CFG_NewTLS12Config`
  - `TLSv1_2_server_method`
    - `HITLS_CFG_NewTLS12Config`
    - `HITLS_CFG_SetEndPoint`
  - `DTLS_client_method`
    - `HITLS_CFG_NewDTLSConfig`
    - `HITLS_CFG_SetEndPoint`
  - `DTLS_method`
    - `HITLS_CFG_NewDTLSConfig`
  - `DTLS_server_method`
    - `HITLS_CFG_NewDTLSConfig`
    - `HITLS_CFG_SetEndPoint`
  - `DTLS_set_timer_cb`
    - `HITLS_SetDtlsTimerCb`
    - `HITLS_CFG_SetDtlsTimerCb`
  - `DTLSv1_2_client_method`
    - `HITLS_CFG_NewDTLS12Config`
    - `HITLS_CFG_SetEndPoint`
  - `DTLSv1_2_method`
    - `HITLS_CFG_NewDTLS12Config`
  - `DTLSv1_2_server_method`
    - `HITLS_CFG_NewDTLS12Config`
    - `HITLS_CFG_SetEndPoint`
- These stay `partial` because:
  - OpenSSL returns `SSL_METHOD *` selectors
  - openHiTLS returns concrete config objects and relies on explicit endpoint selection
- `not_available` remains correct for:
  - `TLSv1_*`
  - `TLSv1_1_*`
  - `DTLSv1_*`
  - `DTLSv1_listen`
  - `DTLS_get_data_mtu`

Representative evidence:
- OpenSSL declarations and docs:
  - [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1937)
  - [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1959)
  - [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L1976)
  - [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2509)
  - [SSL_CTX_new.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/SSL_CTX_new.pod#L20)
  - [DTLS_set_timer_cb.pod](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/doc/man3/DTLS_set_timer_cb.pod#L15)
- openHiTLS public declarations:
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L236)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L352)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L437)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L480)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1004)
  - [hitls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls_config.h#L1684)
  - [hitls.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/tls/hitls.h#L910)
  - [tls_config.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/include/tls_config.h#L53)

Batch 259 inventory:
- total interfaces: `22`
- `partial = 11`
- `not_available = 11`
