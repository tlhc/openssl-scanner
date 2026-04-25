# openHiTLS Compatibility Validation Batch 134

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `SSL_COMP_add_compression_method`
- `SSL_COMP_get0_name`
- `SSL_COMP_get_compression_methods`
- `SSL_COMP_get_id`
- `SSL_COMP_get_name`
- `SSL_COMP_set0_compression_methods`

Status:
- completed

Initial evidence:
- OpenSSL publishes the TLS compression API in [ssl.h.in](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/ssl.h.in#L2167) and implements it in [ssl_ciph.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/ssl/ssl_ciph.c#L1981).
- openHiTLS parses and emits only the null compression method in handshake processing, visible in [parse_client_hello.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/handshake/parse/src/parse_client_hello.c#L156), [recv_client_hello.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/handshake/recv/src/recv_client_hello.c#L2154), and [pack_server_hello.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/tls/handshake/pack/src/pack_server_hello.c#L54).
- No public openHiTLS API was found for registering, querying, or swapping compression methods.

Verdict:
- keep `not_available` for all entries in scope.
