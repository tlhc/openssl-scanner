# openHiTLS Compatibility Validation Batch 213

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl](openssl)

Scope:
- remaining `BIO_*` method / chain / helper family lacking `analysis_doc`

Status:
- completed

Initial evidence:
- OpenSSL keeps a large `BIO` object-model surface in public headers and `crypto/bio`, including:
  - method-object construction and callback slots via `BIO_meth_*`
  - instance helpers like `BIO_ctrl`, `BIO_gets`, `BIO_puts`, `BIO_get_data`, `BIO_set_data`, `BIO_up_ref`
  - chain helpers like `BIO_push`, `BIO_pop`, `BIO_next`
  - constructor/method factories like `BIO_new_*` and `BIO_s_*`
- openHiTLS exposes a public `BSL_UIO` transport abstraction in installed headers, including:
  - method construction via `BSL_UIO_NewMethod`, `BSL_UIO_SetMethod`, `BSL_UIO_FreeMethod`
  - concrete method factories via `BSL_UIO_MemMethod`, `BSL_UIO_FileMethod`, `BSL_UIO_TcpMethod`, `BSL_UIO_UdpMethod`
  - instance helpers via `BSL_UIO_New`, `BSL_UIO_Ctrl`, `BSL_UIO_Puts`, `BSL_UIO_Gets`, `BSL_UIO_GetCtx`, `BSL_UIO_SetCtx`, `BSL_UIO_GetUserData`, `BSL_UIO_SetUserData`, `BSL_UIO_GetIsUnderlyingClosedByUio`, `BSL_UIO_SetIsUnderlyingClosedByUio`, `BSL_UIO_ClearFlags`, `BSL_UIO_TestFlags`, `BSL_UIO_UpRef`, `BSL_UIO_Append`, `BSL_UIO_PopCurrent`, `BSL_UIO_Next`
  - raw socket helpers via `BSL_SAL_SockClose` and `BSL_SAL_SetSockopt`
- openHiTLS does not expose the full OpenSSL `BIO` object model:
  - no public `BIO_callback_ctrl`-style callback registration surface
  - no `BIO_f_*` filter factory family
  - no `BIO_pair` / `BIO_accept` / `BIO_connect` object family matching OpenSSL contracts
  - no index-based `ex_data` table semantics

Verdict:
- keep `available = 0`
- adjust to `partial = 61`
- adjust to `not_available = 91`

Reasoning boundary:
- `partial` covers the parts where openHiTLS has a practical public analogue on `BSL_UIO` or `BSL_SAL`, but the contract still differs:
  - `BIO_meth_*` -> `BSL_UIO_NewMethod` / `BSL_UIO_SetMethod` / `BSL_UIO_FreeMethod`
  - `BIO_ctrl` -> `BSL_UIO_Ctrl`
  - `BIO_ctrl_pending` / `BIO_ctrl_wpending` -> `BSL_UIO_Ctrl(..., BSL_UIO_PENDING/WPENDING, ...)`
  - `BIO_get_data` / `BIO_set_data` -> `BSL_UIO_GetCtx` / `BSL_UIO_SetCtx`
  - `BIO_get_ex_data` / `BIO_set_ex_data` -> `BSL_UIO_GetUserData` / `BSL_UIO_SetUserData`
  - `BIO_get_init` -> `BSL_UIO_Ctrl(..., BSL_UIO_GET_INIT, ...)`
  - `BIO_get_shutdown` / `BIO_set_shutdown` -> `BSL_UIO_GetIsUnderlyingClosedByUio` / `BSL_UIO_SetIsUnderlyingClosedByUio`
  - `BIO_gets` / `BIO_puts` -> `BSL_UIO_Gets` / `BSL_UIO_Puts`
  - `BIO_push` / `BIO_pop` / `BIO_next` -> `BSL_UIO_Append` / `BSL_UIO_PopCurrent` / `BSL_UIO_Next`
  - `BIO_clear_flags` / `BIO_test_flags` -> `BSL_UIO_ClearFlags` / `BSL_UIO_TestFlags`
  - `BIO_up_ref` -> `BSL_UIO_UpRef`
  - `BIO_new_fp` -> `BSL_UIO_New(BSL_UIO_FileMethod()) + BSL_UIO_Ctrl(..., BSL_UIO_FILE_PTR, ...)`
  - `BIO_new_dgram` / `BIO_s_datagram` -> `BSL_UIO_New(BSL_UIO_UdpMethod())`
  - `BIO_closesocket` -> `BSL_SAL_SockClose`
  - `BIO_set_tcp_ndelay` -> `BSL_SAL_SetSockopt(..., SAL_NET_TCP_NODELAY, ...)`
- `not_available` covers the parts where openHiTLS still lacks the practical public OpenSSL-shaped surface:
  - `BIO_callback_ctrl`
  - `BIO_get_callback*` / `BIO_set_callback*`
  - `BIO_f_*`
  - `BIO_dump*` / `BIO_printf` / `BIO_vprintf` / `BIO_snprintf` / `BIO_vsnprintf`
  - `BIO_new_accept` / `BIO_new_bio_pair` / `BIO_new_bio_dgram_pair` / `BIO_new_CMS` / `BIO_new_PKCS7` / `BIO_new_ssl`
  - `BIO_s_accept` / `BIO_s_bio` / `BIO_s_core` / `BIO_s_dgram_pair` / `BIO_s_log` / `BIO_s_null`
  - retry-reason and callback-arg helpers
  - deprecated resolver helpers and line-oriented wrappers without a public direct analogue

Key source-backed corrections in this batch:
- `BIO_get_ex_data` / `BIO_set_ex_data`
  - OpenSSL uses index-based `CRYPTO_*_ex_data`
  - openHiTLS exposes one public user-data slot on `BSL_UIO`
  - practical user-data replacement exists, so these move to `partial`
- `BIO_get_init`
  - OpenSSL exposes `BIO_get_init`
  - openHiTLS exposes `BSL_UIO_Ctrl(..., BSL_UIO_GET_INIT, ...)`
  - public readback exists, so this moves to `partial`
- `BIO_get_shutdown` / `BIO_set_shutdown`
  - OpenSSL stores shutdown ownership on the `BIO`
  - openHiTLS exposes `BSL_UIO_GetIsUnderlyingClosedByUio` / `BSL_UIO_SetIsUnderlyingClosedByUio`
  - same resource-ownership role exists through a different boolean contract
- `BIO_new_fp`
  - OpenSSL uses `BIO_s_file()` plus `BIO_set_fp`
  - openHiTLS exposes `BSL_UIO_FileMethod` plus `BSL_UIO_Ctrl(..., BSL_UIO_FILE_PTR, closeFlag, stream)`
- `BIO_new_dgram` / `BIO_s_datagram`
  - openHiTLS exposes `BSL_UIO_UdpMethod` publicly
- `BIO_closesocket`
  - openHiTLS exposes `BSL_SAL_SockClose`
- `BIO_set_tcp_ndelay`
  - openHiTLS exposes `BSL_SAL_SetSockopt` with `SAL_NET_IPPROTO_TCP` and `SAL_NET_TCP_NODELAY`

Representative evidence:
- OpenSSL declarations:
  - [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L720)
  - [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L749)
  - [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L765)
  - [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L901)
  - [bio.h.in](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/include/openssl/bio.h.in#L963)
- OpenSSL implementations:
  - [bio_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bio_lib.c#L512)
  - [bio_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bio_lib.c#L674)
  - [bio_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bio_lib.c#L767)
  - [bio_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bio_lib.c#L785)
  - [bio_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bio_lib.c#L858)
  - [bio_lib.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bio_lib.c#L938)
  - [bio_meth.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bio_meth.c#L37)
  - [bss_file.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bss_file.c#L97)
  - [bss_dgram.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bss_dgram.c#L257)
  - [bss_sock.c](https://github.com/openssl/openssl/blob/6115286faeb8fb023d79660e973a3252b142f6c1/crypto/bio/bss_sock.c#L68)
- openHiTLS declarations:
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L256)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L296)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L320)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L328)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L346)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L441)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L456)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L471)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L480)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L516)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L542)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L552)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L562)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L580)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L589)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L598)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L620)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L632)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L644)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L656)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L666)
  - [bsl_uio.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_uio.h#L685)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L807)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L871)
  - [bsl_sal.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_sal.h#L888)
- openHiTLS implementations:
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L30)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L99)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L135)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L221)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L317)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L337)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L352)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L402)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L424)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L450)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L474)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L515)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L526)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L612)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L631)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L648)
  - [uio_abstraction.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_abstraction.c#L662)
  - [uio_file.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_file.c#L157)
  - [uio_file.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_file.c#L253)
  - [uio_file.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_file.c#L322)
  - [uio_udp.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/uio/src/uio_udp.c#L333)

Batch 213 inventory:
- total interfaces: `152`
- `partial = 61`
- `not_available = 91`
