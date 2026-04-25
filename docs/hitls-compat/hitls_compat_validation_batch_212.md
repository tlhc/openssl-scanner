# openHiTLS Compatibility Validation Batch 212

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- `BIO_ADDR / BIO_ADDRINFO / BIO` network helper family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL exposes a broad network-helper surface around:
  - `BIO_ADDR *`
  - `BIO_ADDRINFO *`
  - `BIO_lookup(_ex)`
  - `BIO_socket`
  - `BIO_connect`
  - `BIO_bind`
  - `BIO_listen`
  - `BIO_accept_ex`
  - `BIO_sock_error`
  - `BIO_socket_ioctl`
- openHiTLS public installed headers expose a raw socket/helper layer in `bsl_sal.h`, including:
  - `BSL_SAL_Socket`
  - `BSL_SAL_SockBind`
  - `BSL_SAL_SockConnect`
  - `BSL_SAL_SockListen`
  - `BSL_SAL_Ioctlsocket`
  - `BSL_SAL_SockGetLastSocketError`
- openHiTLS does not expose the OpenSSL `BIO_ADDR` / `BIO_ADDRINFO` object family or a `BIO_lookup`-style name-resolution surface in installed public headers.

Verdict:
- keep `available = 0`
- adjust to `partial = 6`
- adjust to `not_available = 28`

Reasoning boundary:
- `partial` is limited to the helpers with a direct public raw-socket analogue:
  - `BIO_socket -> BSL_SAL_Socket`
  - `BIO_bind -> BSL_SAL_SockBind`
  - `BIO_connect -> BSL_SAL_SockConnect`
  - `BIO_listen -> BSL_SAL_SockListen`
  - `BIO_sock_error -> BSL_SAL_SockGetLastSocketError`
  - `BIO_socket_ioctl -> BSL_SAL_Ioctlsocket`
- `not_available` covers the rest of the family:
  - all `BIO_ADDR*`
  - all `BIO_ADDRINFO*`
  - `BIO_lookup(_ex)`
  - `BIO_accept(_ex)`
  - `BIO_sock_init`
  - `BIO_sock_non_fatal_error`
  - `BIO_sock_should_retry`
  - `BIO_socket_nbio`
  - `BIO_socket_wait`
- The shared blocker is the missing `BIO_ADDR/BIO_ADDRINFO` object model and missing public name-resolution / retry helper surface.
