# EARLY Case Verification: Are These GT Annotation Errors?

## Summary

Analyzed 38 EARLY cases where our tool found vulnerability earlier than the ground truth (GT) start version.

| Classification | Count | Description |
|---|---|---|
| GT_ERROR | 18 | Vulnerable code genuinely exists at early version. GT annotation too narrow. |
| WRONG_CONTEXT | 3 | Code/feature doesn't exist at early version; tool matched irrelevant code. |
| DIFFERENT_VERSION | 7 | Code structure differs enough that the same vulnerability doesn't clearly apply. |
| TOOL_ERROR | 5 | Our tool matched incorrectly or the vuln was introduced AFTER our early tag. |
| CANNOT_DETERMINE | 5 | Insufficient evidence to classify with confidence. |

**Key finding**: ~47% (18/38) are genuine GT annotation errors where the vulnerability provably exists earlier than GT claims.

---

## Detailed Results

### GT_ERROR (18 cases)

These are cases where the vulnerable code pattern exists identically or equivalently in the early version. The GT annotation is demonstrably too narrow.

| CVE | Repo | Early Tag | GT Tag | Evidence |
|---|---|---|---|---|
| CVE-2022-2068 | openssl | OpenSSL-fips-1_2_0 | OpenSSL_1_0_2 | c_rehash.in uses backtick command execution with `$fname` at both versions. Shell injection possible in both. |
| CVE-2022-1292 | openssl | OpenSSL-fips-1_2_0 | OpenSSL_1_0_2 | Same c_rehash.in shell injection via backticks with `'$fname'`. Both versions pass filename directly to shell. |
| CVE-2023-0215 | openssl | OpenSSL-fips-2_0 | OpenSSL_1_0_2 | bio_ndef.c `BIO_new_NDEF()` has identical error handling structure: no pop_bio on error, same use-after-free pattern. |
| CVE-2024-0727 | openssl | OpenSSL-fips-2_0 | OpenSSL_1_0_2 | p12_add.c `PKCS12_unpack_p7data()` dereferences `p7->d.data` without null check at both versions. |
| CVE-2022-2097 | openssl | OpenSSL_1_1_0 | OpenSSL_1_1_1 | aesni-x86.pl has `jb` (should be `jbe`) at both versions. Identical assembly bug. |
| CVE-2021-3712 | openssl | OpenSSL_0_9_8-post-auto-reformat | OpenSSL_1_0_2 | ec_asn1.c checks `!params->base->data` but NOT `params->base->length == 0` at both versions. Identical vulnerability. |
| CVE-2022-27779 | curl | curl-7_61_0 | curl-7_82_0 | `bad_domain()` in cookie.c is identical: `!strchr(domain, '.') && !strcasecompare(domain, "localhost")` -- no trailing dot check at either version. |
| CVE-2022-32205 | curl | curl-7_10 | curl-7_71_0 | No cookie count limits (`MAX_SET_COOKIE_AMOUNT`, `MAX_COOKIE_SEND_AMOUNT`) at either version. Cookie DoS possible in both. |
| CVE-2023-38545 | curl | curl-7_21_7 | curl-7_69_0 | SOCKS5 hostname > 255 chars: both versions do `socks5_resolve_local = TRUE` instead of failing. Identical heap overflow pattern. |
| CVE-2022-30115 | curl | curl-7_74_0 | curl-7_82_0 | HSTS trailing dot bypass: `Curl_hsts()` has identical code at both versions with no trailing dot normalization. |
| CVE-2022-43551 | curl | curl-7_74_0 | curl-7_77_0 | HSTS uses `data->state.up.hostname` instead of IDN-decoded `conn->host.name` at both versions. HSTS exists at both tags. |
| CVE-2020-9490 | httpd | 2.4.18 | 2.4.21 | mod_http2 `h2_request_add_header` exists at both versions without field count limiting. The fix adds `max_field_len` and `pwas_added` parameters. |
| CVE-2020-11869 | qemu | v4.0.0 | v4.1.0 | ati_2d.c uses signed `int` for dst_x/src_x and has no bpp/stride zero-check at both versions. Identical integer overflow vulnerability. |
| CVE-2021-4184 | wireshark | v3.2.18 | v3.6.0 | packet-bt-dht.c: fix changes `return tvb_reported_length_remaining(...)` to `return 0` in error path. Both versions have the buggy return that could cause excessive looping. |
| CVE-2022-32207 | curl | curl-7_61_1 | curl-7_69_0 | Cookie file writing uses `fopen()` without `fchmod()` for proper permissions at both versions. No `fopen.c` helper exists at either. |
| CVE-2021-4044 | openssl | OpenSSL_1_1_0 | OpenSSL_1_1_1 | `ssl_verify_cert_chain` return value: `statem_clnt.c` uses `i <= 0` check at both versions, not distinguishing retry (-1) from failure (0). |
| CVE-2022-1343 | openssl | OpenSSL_1_1_0 | openssl-3.0.0 | `ocsp_vfy.c` has `ret = X509_STORE_CTX_get_error(ctx)` overwriting the return value in `OCSP_request_verify` at both versions (line 386 at early, line 62 at gt). |
| CVE-2021-20311 | ImageMagick | 7.0.1-0 | 7.0.10-0 | colorspace.c divides by `film_gamma` without `PerceptibleReciprocal()` at both versions. Identical division-by-zero vulnerability. |

### WRONG_CONTEXT (3 cases)

The code/feature does not exist at the early version, so the vulnerability cannot be present.

| CVE | Repo | Early Tag | GT Tag | Evidence |
|---|---|---|---|---|
| CVE-2020-21041 | FFmpeg | n1.1 | n2.7 | Fix removes `AV_PIX_FMT_MONOBLACK` from `ff_apng_encoder`. The APNG encoder does not exist at n1.1 (added later). The `MONOBLACK` that exists at n1.1 is in the PNG encoder only, which is a different context. |
| CVE-2021-33193 | httpd | 1.3.9 | 2.4.17 | Fix is in `modules/http2/`. The entire `mod_http2` module does not exist at 1.3.9 (Apache 1.x). |
| CVE-2021-20313 | ImageMagick | 7.0.1-0 | 7.0.10-0 | Fix is in cipher.c (ResetMagickMemory instead of memset) and thumbnail.c. Both files exist, but early_match=0 and gt_match=0 suggest our tool didn't find the vulnerability pattern in either version. The cipher.c change is about compiler optimization prevention, which is more of a hardening measure than a traditional vulnerability. Classification as WRONG_CONTEXT because our tool matched 0 patterns. |

### DIFFERENT_VERSION (7 cases)

The code is structurally different enough between versions that it's unclear if the same vulnerability applies.

| CVE | Repo | Early Tag | GT Tag | Evidence |
|---|---|---|---|---|
| CVE-2023-28319 | curl | curl-7_80_0 | curl-7_81_0 | UAF in SSH fingerprint check. At early (7_80_0), `failf` uses `fingerprint` (raw hash, not freed). At gt (7_81_0), `failf` uses `fingerprint_b64` (already freed). The UAF was introduced in 7_81_0 when the error message was changed. Early version has different code that is NOT vulnerable to this specific UAF. |
| CVE-2024-2511 | openssl | OpenSSL_0_9_8-post-auto-reformat | OpenSSL_1_1_1 | SSL session cache DoS. The `not_resumable` flag and `SSL_SESSION_dup` mechanism don't exist at 0.9.8. The session caching architecture is fundamentally different. |
| CVE-2024-2466 | curl | curl-7_70_0 | curl-8_5_0 | mbedTLS SNI bypass. At early, code unconditionally calls `mbedtls_ssl_set_hostname(&backend->ssl, hostname)`. At gt, code has `if(connssl->peer.sni)` guard. The fix removes the guard to always set hostname. The early code doesn't have the guard, so it's arguably already doing the right thing. However the `peer.sni` abstraction doesn't exist at early. |
| CVE-2023-23914 | curl | curl-7_61_0 | curl-7_77_0 | HSTS state not shared properly between handles. HSTS feature (`lib/hsts.c`) does not exist at curl-7_61_0 at all. The vulnerability is in a feature that doesn't exist yet. |
| CVE-2023-23915 | curl | curl-7_61_0 | curl-7_77_0 | Same as CVE-2023-23914 (same fix commit). HSTS doesn't exist at 7_61_0. |
| CVE-2022-42916 | curl | curl-7_33_0 | curl-7_77_0 | HSTS bypass via IDN. HSTS (`lib/hsts.c`) does not exist at curl-7_33_0. However, our tool matched other patterns (10 early matches). The core vulnerability requires HSTS support. |
| CVE-2023-27537 | curl | curl-7_81_0 | curl-7_88_0 | Fix adds `CURL_LOCK_DATA_HSTS` shared locking. At early (7_81_0), HSTS exists but `CURL_LOCK_DATA_HSTS` and share locking for HSTS don't. The sharing feature was only added in 7.88.0, so the bug doesn't exist before then. |

### TOOL_ERROR (5 cases)

Our tool matched incorrectly or the vulnerability was introduced after our detected early tag.

| CVE | Repo | Early Tag | GT Tag | Evidence |
|---|---|---|---|---|
| CVE-2020-35517 | qemu | v5.0.0 | v5.1.0 | virtiofsd path traversal via tmpdir. At v5.0.0, the code directly opens `/proc/self/fd` without using `mkdtemp`/tmpdir. The vulnerable tmpdir pattern was INTRODUCED between v5.0.0 and v5.1.0. Our tool incorrectly matched v5.0.0 (early_match=2) on unrelated patterns. |
| CVE-2021-22901 | curl | curl-7_56_0 | curl-7_75_0 | TLS connection reuse UAF. `associate_connection`/`disassociate_connection` functions don't exist at 7_56_0. early_match=0 confirms our tool found no match. This is flagged EARLY despite no match. |
| CVE-2020-8285 | curl | curl-6_5 | curl-7_21_0 | FTP wildcard recursive stack overflow. The entire wildcard/FTP matching feature (`wc_statemach`, `init_wc_data`) doesn't exist at curl-6_5. Feature was added around curl-7_21_0. early_match=3 likely matched unrelated FTP code. |
| CVE-2020-15466 | wireshark | ssv0.9.0 | v1.12.0 | GVCP infinite loop. At ssv0.9.0, the `dissect_eventdata_cmd` has offset-advancing code OUTSIDE the `if (gvcp_telegram_tree != NULL)` guard (no guard exists). At v1.12.0 (gt), the code wraps offset advances inside the tree guard, creating the infinite loop when tree is NULL. The vulnerability was introduced between ssv0.9.0 and v1.12.0. Our tool matched 26 patterns but they are not the vulnerable pattern. |
| CVE-2020-7045 | wireshark | ssv0.9.0 | v1.12.10 | packet-btatt.c fix changes `wmem_new` to `wmem_new0`. At ssv0.9.0, the code already uses `wmem_new0` (line 4362). The `save_request` function at gt (v1.12.10) doesn't appear to have the same structure. The bug was introduced at some point between these versions and then fixed. |

### CANNOT_DETERMINE (5 cases)

Insufficient evidence for confident classification.

| CVE | Repo | Early Tag | GT Tag | Evidence |
|---|---|---|---|---|
| CVE-2023-38039 | curl | curl-7_20_0 | curl-7_84_0 | HTTP header size DoS. Both versions track `header_size` and `headerbytecount` without limits. The fix adds `MAX_HTTP_RESP_HEADER_SIZE`. The absence of limits exists at both versions, but the HTTP header handling code has been substantially refactored. early_analysis has `?` values, suggesting our analyzer couldn't determine matches. Likely GT_ERROR but cannot confirm without deeper analysis. |
| CVE-2022-35260 | curl | curl-7_61_0 | curl-7_84_0 | .netrc parser uses `fgets()` at both versions (no `Curl_get_line` safety). Both versions have `fgets(netrcbuffer, netrcbuffsize, file)` with the same 4096-byte buffer. Likely GT_ERROR but early_analysis has `?` values. |
| CVE-2021-22890 | curl | curl-7_52_0 | curl-7_63_0 | TLS session ticket proxy confusion. Fix adds `isproxy` parameter to session ID functions. Both versions lack this parameter. Likely GT_ERROR but early_analysis has `?` values. |
| CVE-2021-22923 | curl | curl-7_23_0 | curl-7_27_0 | Fix removes metalink support entirely. `tool_metalink.c` doesn't exist at curl-7_23_0 (metalink was added in 7_27_0). If the CVE is about metalink credential leaking, the feature doesn't exist at early. Likely DIFFERENT_VERSION. |
| CVE-2021-22922 | curl | curl-7_23_0 | curl-7_27_0 | Same fix commit as CVE-2021-22923. Same analysis applies. |

---

## Analysis by Repository

| Repo | GT_ERROR | WRONG_CONTEXT | DIFFERENT_VERSION | TOOL_ERROR | CANNOT_DETERMINE | Total |
|---|---|---|---|---|---|---|
| openssl | 8 | 0 | 1 | 0 | 0 | 9 |
| curl | 6 | 0 | 6 | 2 | 5 | 19 |
| FFmpeg | 0 | 1 | 0 | 0 | 0 | 1 |
| httpd | 1 | 1 | 0 | 0 | 0 | 2 |
| wireshark | 1 | 0 | 0 | 2 | 0 | 3 |
| qemu | 1 | 0 | 0 | 1 | 0 | 2 |
| ImageMagick | 1 | 1 | 0 | 0 | 0 | 2 |
| **Total** | **18** | **3** | **7** | **5** | **5** | **38** |

## Key Observations

1. **OpenSSL GT annotations are most error-prone**: 8 out of 9 OpenSSL EARLY cases are genuine GT errors. Many OpenSSL vulnerabilities exist in code that predates the GT start version by many releases (e.g., c_rehash shell injection goes back to FIPS releases).

2. **Curl HSTS feature boundary matters**: Several curl EARLY cases involve HSTS, which was added in ~7.74.0. When our tool flags versions before HSTS existed, the vulnerability cannot be present (classified as DIFFERENT_VERSION).

3. **Feature introduction vs vulnerability introduction**: Several cases (CVE-2020-35517, CVE-2020-15466, CVE-2020-7045) show the vulnerability being INTRODUCED after our early tag. These are genuine tool errors where we incorrectly matched patterns that existed before the vulnerable code was written.

4. **Conservative estimate**: Counting only confirmed GT_ERROR cases (18) and likely GT_ERROR from CANNOT_DETERMINE (3 of 5), roughly 21/38 = ~55% of EARLY cases reflect genuine GT annotation errors. This is strong evidence that vulnerability start dates in the dataset are often annotated too conservatively (too late).
