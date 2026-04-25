# openHiTLS Compatibility Validation Batch 035

Validated against:
- scanner data file: [hitls_compat.json](oh/scanner/src/openssl_scanner/data/hitls_compat.json)
- openHiTLS source tree: [openhitls-upstream](openhitls-upstream)
- OpenSSL reference tree: [openssl-3.0.9](openssl-3.0.9)

Scope:
- `OBJ_obj2nid`
- `OBJ_nid2sn`
- `OBJ_txt2obj`
- `EVP_get_digestbyname`

Status:
- completed

Initial evidence:
- This is the next compact high-frequency helper batch without `analysis_doc`.
- Current scan aggregation shows:
  - `OBJ_obj2nid`: 11 repos
  - `OBJ_nid2sn`: 9 repos
  - `OBJ_txt2obj`: 8 repos
  - `EVP_get_digestbyname`: 8 repos
- The whole batch turns on one rule:
  - openHiTLS public `BSL_OBJ_*` APIs cover OID/CID conversion, not OpenSSL's full object/name registry

## 1. `OBJ_obj2nid`
- OpenSSL declaration/implementation: [objects.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/objects.h#L69), [obj_dat.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/objects/obj_dat.c#L326)
- openHiTLS declaration/implementation: [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L737), [bsl_obj.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/obj/src/bsl_obj.c#L258)
- Verdict: keep `partial`
- Why: openHiTLS can resolve an encoded OID to a `BslCid` through `BSL_OBJ_GetCID`, but not from an OpenSSL `ASN1_OBJECT *`.

## 2. `OBJ_nid2sn`
- OpenSSL declaration/implementation: [objects.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/objects.h#L68), [obj_dat.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/objects/obj_dat.c#L250)
- openHiTLS public/internal evidence: [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L737), [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L744), [bsl_obj.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/obj/src/bsl_obj.c#L467)
- Verdict: change to `not_available`
- Why: openHiTLS does not expose a public short-name lookup by CID. The closest public APIs return CID or OID; name lookup exists only in internal code.

## 3. `OBJ_txt2obj`
- OpenSSL declaration/implementation: [objects.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/objects.h#L71), [obj_dat.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/objects/obj_dat.c#L362)
- openHiTLS declaration/implementation: [bsl_obj.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/bsl/bsl_obj.h#L755), [bsl_obj.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/bsl/obj/src/bsl_obj.c#L739)
- Verdict: change to `partial`
- Why: openHiTLS can convert numeric dotted OID strings through `BSL_OBJ_GetOidFromNumericString`, but it does not resolve short-name/long-name object names the way OpenSSL does.

## 4. `EVP_get_digestbyname`
- OpenSSL declaration/implementation: [evp.h](https://github.com/openssl/openssl/blob/openssl-3.0.9/include/openssl/evp.h#L1172), [names.c](https://github.com/openssl/openssl/blob/openssl-3.0.9/crypto/evp/names.c#L117)
- openHiTLS public/app-layer evidence: [app_list.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/apps/include/app_list.h#L51), [app_list.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/apps/src/app_list.c#L615), [app_dgst.c](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/apps/src/app_dgst.c#L694), [crypt_eal_md.h](https://gitcode.com/openHiTLS/openhitls/blob/d9cc8577/include/crypto/crypt_eal_md.h#L61)
- Verdict: keep `not_available`
- Why: openHiTLS has app-layer name-to-CID lookup helpers, but no public library API equivalent to `EVP_get_digestbyname`.

## Batch 035 summary

Keep `partial`:
- `OBJ_obj2nid`

Change to `partial`:
- `OBJ_txt2obj`

Change to `not_available`:
- `OBJ_nid2sn`

Keep `not_available`:
- `EVP_get_digestbyname`

Main observation:
- openHiTLS covers the OID/CID path well.
- It does not expose OpenSSL's public object-name registry as a library API.
