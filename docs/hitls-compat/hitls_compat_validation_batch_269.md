# hitls_compat validation batch 269 - factual-error correction 2026-04-25

## Scope

85 truth-library entries whose previous `hitls_equivalent` cited openHiTLS
identifiers that are not in the installed public headers (`include/`). All
citations were re-verified against openHiTLS upstream source
(commit `d9cc8577`, reachable at
`https://gitcode.com/openHiTLS/openhitls/tree/d9cc8577`).

## Migration result

- all 85 downgraded to `not_available` with `hitls=null`.
- none kept as `partial`: each prior `partial` label was attached to a
  bogus citation chain (internal-only BSL/CRYPT_EAL symbol OR fabricated
  HITLS symbol). Ostensibly "partial" replacement paths relying on
  `BSL_ASN1_DecodeTemplate` + per-symbol post-processing were also dropped
  after per-symbol re-examination showed the semantic gap (integer extract,
  time compare, text print) has no public helper.

## Cluster breakdown

### print_key (26 entries) - DSA/EC/RSA/DH print-key helpers
`CRYPT_EAL_PrintPubkey` / `CRYPT_EAL_PrintPrikey` / `CRYPT_EAL_GetRsaPssPara`
live in `crypto/codecskey/src/crypt_codecskey_print.c` and are NOT declared
in any `include/crypto/*.h`.

### conf (22 entries) - CONF/NCONF config subsystem
`BSL_CONF_*` lives under `bsl/conf/include/` + `bsl/conf/src/`, outside
the installed `include/bsl/` tree. Removes prior internal contradiction
where some CONF_* entries were already `not_available` ("No CONF/NCONF
config subsystem in openHiTLS public API") while siblings claimed
`BSL_CONF_*` as partial equivalents.

### asn1_primitive (11 entries) - ASN1_INTEGER/ENUMERATED/TIME getters and prints
`BSL_ASN1_DecodePrimitiveItem` is defined in `bsl/asn1/src/bsl_asn1.c` with
no declaration in `include/bsl/bsl_asn1.h`. Public
`BSL_ASN1_DecodeTemplate` exists but only returns raw `BSL_ASN1_Buffer`;
per-symbol post-processing (integer extract, time comparison, text print)
has no public helper (BSL_PRINT_Time is internal).

### lhash (10 entries) - OPENSSL_LH_* generic hash table
`BSL_HASH_*` is internal (used by provider registry and obj cid tables)
and not exposed through `include/bsl/`.

### cms (7 entries) - i2d_CMS_* encoders
`HITLS_CMS_GenBuff` / `HITLS_CMS_GenFile` live only in sdv test code
(`testcode/sdv/testcase/pki/cms/`). Public CMS API (
`include/pki/hitls_pki_cms.h`) has no "encode pre-built CMS to DER" path:
only ParseBuff/ParseFile (decode) and DataSign/DataVerify/DataInit+Update
+DataFinal (streaming sign/verify that couples signing with encoding).

### time_offset (4 entries) - ASN1_TIME_adj/check family
`BSL_DateTimeAddDaySecond` / `BSL_DateTimeCheck` are internal
(`bsl/sal/src/sal_time.c`, `bsl/asn1/src/bsl_asn1.c`). Public time API
exposes `BSL_SAL_UtcTimeToDateConvert` and `BSL_SAL_DateTimeCompare` but
no offset-arithmetic helper.

### ca_store (4 entries) - X509_STORE_load_file family
`HITLS_CFG_LoadCAFile` was FABRICATED - the symbol does not exist anywhere
in openHiTLS source. Nearest public parser is
`HITLS_X509_CertParseBundleFile` in `include/pki/hitls_pki_x509.h`, but no
public integration path into a generic OpenSSL-compatible X509
verification store is installed.

### asn1_utf8 (1 entry) - ASN1_STRING_to_UTF8
`BSL_ASN1_ToUtf8String` is internal (`bsl/asn1/src/bsl_asn1.c`).

## Complete symbol list

- `ASN1_ENUMERATED_get`
- `ASN1_GENERALIZEDTIME_check`
- `ASN1_GENERALIZEDTIME_print`
- `ASN1_INTEGER_get`
- `ASN1_STRING_to_UTF8`
- `ASN1_TIME_adj`
- `ASN1_TIME_check`
- `ASN1_TIME_cmp_time_t`
- `ASN1_TIME_compare`
- `ASN1_TIME_diff`
- `ASN1_TIME_print_ex`
- `ASN1_TIME_to_tm`
- `ASN1_UTCTIME_adj`
- `ASN1_UTCTIME_check`
- `ASN1_UTCTIME_cmp_time_t`
- `ASN1_UTCTIME_print`
- `CONF_dump_bio`
- `CONF_dump_fp`
- `CONF_free`
- `CONF_get_number`
- `CONF_get_section`
- `CONF_get_string`
- `CONF_load`
- `CONF_load_bio`
- `CONF_load_fp`
- `DSA_bits`
- `DSA_free`
- `DSA_generate_key`
- `DSA_generate_parameters_ex`
- `DSA_get0_g`
- `DSA_get0_key`
- `DSA_get0_p`
- `DSA_get0_pqg`
- `DSA_get0_priv_key`
- `DSA_get0_pub_key`
- `DSA_get0_q`
- `DSA_get_ex_data`
- `DSA_new`
- `DSA_print`
- `DSA_print_fp`
- `DSA_security_bits`
- `DSA_set0_key`
- `DSA_set0_pqg`
- `DSA_set_ex_data`
- `DSA_sign`
- `DSA_size`
- `DSA_up_ref`
- `DSA_verify`
- `NCONF_default`
- `NCONF_dump_bio`
- `NCONF_dump_fp`
- `NCONF_free`
- `NCONF_get_number_e`
- `NCONF_get_section`
- `NCONF_get_section_names`
- `NCONF_get_string`
- `NCONF_load`
- `NCONF_load_bio`
- `NCONF_load_fp`
- `NCONF_new`
- `NCONF_new_ex`
- `OPENSSL_LH_delete`
- `OPENSSL_LH_doall`
- `OPENSSL_LH_doall_arg`
- `OPENSSL_LH_flush`
- `OPENSSL_LH_free`
- `OPENSSL_LH_insert`
- `OPENSSL_LH_new`
- `OPENSSL_LH_num_items`
- `OPENSSL_LH_retrieve`
- `OPENSSL_LH_strhash`
- `RSA_get0_pss_params`
- `RSA_print`
- `RSA_print_fp`
- `X509_STORE_load_file`
- `X509_STORE_load_file_ex`
- `X509_STORE_load_locations`
- `X509_STORE_load_locations_ex`
- `i2d_CMS_ContentInfo`
- `i2d_CMS_bio`
- `i2d_CMS_bio_stream`
- `i2d_PKCS7`
- `i2d_PKCS7_bio`
- `i2d_PKCS7_bio_stream`
- `i2d_PKCS7_fp`
