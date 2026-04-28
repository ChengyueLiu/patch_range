# Analysis of EARLY Cases: Tool Finds VULN Before Ground Truth Start Version

These are cases where our tool classified a version as VULN that occurs **before** the
ground truth (GT) says the vulnerability started. For each case, we compare the actual
code in the EARLY version vs the GT start version to determine whether the ground truth
is wrong or our tool is wrong.

## Classification Key

- **GT_ERROR**: Vulnerability genuinely exists earlier than GT says. GT affected range is too narrow.
- **WRONG_CONTEXT**: Our tool matched code in a different context; the vulnerability does not exist in the early version.
- **PARTIAL_MATCH**: Some vulnerability indicators exist but the actual vulnerability mechanism is different.
- **OTHER**: Does not fit above categories.

---

## CVE-2023-38039 (curl) -- GT_ERROR

| Field | Value |
|-------|-------|
| Our finding | VULN at `curl-7_20_0` |
| GT start | `curl-7_84_0` |
| Distance | -108 tags |
| CWE | CWE-770 (Allocation of Resources Without Limits) |
| Fixing commit | `3ee79c1674fd6f99e8efca52cd7510e08b766770` |

### What the fix does

The fix adds `Curl_bump_headersize()` with a `MAX_HTTP_RESP_HEADER_SIZE` (300 KB) limit.
Before the fix, `data->info.header_size` and `data->req.headerbytecount` were accumulated
without any bounds check, allowing a malicious server to send unbounded HTTP headers and
exhaust memory.

### Code comparison

**curl-7_20_0** (`lib/http.c` lines ~3285-3286):
```c
data->info.header_size += (long)headerlen;
data->req.headerbytecount += (long)headerlen;
```

**curl-7_84_0** (`lib/http.c` lines ~4060-4061):
```c
data->info.header_size += (long)headerlen;
data->req.headerbytecount += (long)headerlen;
```

Both have a second accumulation site as well. Neither version has any size limit.
No `MAX_HTTP_RESP_HEADER_SIZE` constant exists in either version. The code is functionally
identical in both versions -- unbounded header accumulation with no limit check.

### Verdict: **GT_ERROR**

The vulnerability (no limit on accumulated HTTP response header size) exists in both
curl-7_20_0 and curl-7_84_0. The code patterns are virtually identical. The GT affected
range starting at curl-7_84_0 is too narrow; the vulnerability has existed since at least
curl-7_20_0 (and likely since the HTTP header parsing code was first written). The GT
likely derived its range from the advisory, which may have only tested recent versions.

---

## CVE-2023-38545 (curl) -- WRONG_CONTEXT

| Field | Value |
|-------|-------|
| Our finding | VULN at `curl-7_21_7` |
| GT start | `curl-7_69_0` |
| Distance | -72 tags |
| CWE | CWE-787 (Out-of-bounds Write) |
| Fixing commit | `fb4415d8aee6c1045be932a34fe6107c2f5ed147` |

### What the fix does

In SOCKS5 proxy handling, when a hostname exceeds 255 characters, the code previously
attempted to fall back from remote (proxy-side) DNS resolution to local resolution by
setting `socks5_resolve_local = TRUE`. The fix changes this to return an error
(`CURLPX_LONG_HOSTNAME`) instead of attempting the fallback.

### Code comparison

**curl-7_21_7** (`lib/socks.c`, synchronous blocking code):
```c
bool socks5_resolve_local = (bool)(conn->proxytype == CURLPROXY_SOCKS5);
const size_t hostname_len = strlen(hostname);

/* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
if(!socks5_resolve_local && hostname_len > 255) {
    infof(conn->data,"SOCKS5: server resolving disabled for hostnames of "
          "length > 255 [actual len=%zu]\n", hostname_len);
    socks5_resolve_local = TRUE;
}
```

Later in the **same function execution**:
```c
if(!socks5_resolve_local) {
    socksreq[4] = (char) hostname_len; /* address length */
    memcpy(&socksreq[5], hostname, hostname_len); /* buffer overflow here */
}
else {
    /* local DNS resolution -- safe path, hostname not copied to socksreq */
    Curl_resolv(conn, hostname, remote_port, &dns);
}
```

In curl-7_21_7, this is a single synchronous function (`Curl_SOCKS5`). When `hostname_len > 255`,
the flag is set to TRUE, and the subsequent `if(!socks5_resolve_local)` check correctly
skips the dangerous `memcpy`. **The fallback works correctly.**

**curl-7_69_0** (non-blocking state machine, introduced by commit `4a4b63daaa`):
The same fallback logic exists, but the code was rewritten as a state machine (`do_SOCKS5`
with `CONNECT_SOCKS_INIT`, `CONNECT_RESOLVE_REMOTE`, etc.). The state transitions cause the
`socks5_resolve_local = TRUE` assignment to not properly prevent the buffer overflow in a
later state, because the variable is re-evaluated or the state machine jumps bypass the
check. The CVE fix commit message confirms: "the state machine attempted to change the
remote resolve to a local resolve if the hostname was longer than 255 characters.
Unfortunately that did not work as intended."

### Verdict: **WRONG_CONTEXT**

Our tool matched the `socks5_resolve_local = TRUE` pattern and the `memcpy` of hostname,
which are syntactically identical between versions. However, the vulnerability was
introduced specifically by the conversion to a non-blocking state machine in curl-7_69_0
(commit `4a4b63daaa`, "socks: make the connect phase non-blocking"). In the synchronous
version at curl-7_21_7, the fallback mechanism works correctly. The vulnerability is a
**semantic** bug in state machine transitions, not a syntactic code pattern.

---

## CVE-2022-2068 (openssl) -- GT_ERROR

| Field | Value |
|-------|-------|
| Our finding | VULN at `OpenSSL-fips-1_2_0` |
| GT start | `OpenSSL_1_0_2` |
| Distance | -144 tags |
| CWE | CWE-78 (OS Command Injection) |
| Fixing commit | `2c9c35870601b4a44d86ddbf512b38df38285cfa` |

### What the fix does

The fix rewrites `tools/c_rehash.in` to eliminate shell injection vectors:
1. Replaces backtick shell execution (`` `"$openssl" x509 ... -in '$fname'` ``) with a
   `compute_hash()` function using proper argument passing
2. Replaces `system("cp", $fname, $hash)` with a safe `copy_file()` function using
   three-argument `open()`
3. Replaces two-argument `open IN, $fname` with three-argument `open(my $in, "<", $fname)`

### Code comparison

**OpenSSL-fips-1_2_0** (`tools/c_rehash.in`, from 2007):
```perl
my ($hash, $fprint) = `"$openssl" x509 -hash -fingerprint -noout -in '$fname'`;
# ...
system ("cp", $fname, $hash);
# ...
open IN, $fname;
```

**OpenSSL_1_0_2** (`tools/c_rehash.in`, from 2015):
```perl
my ($hash, $fprint) = `"$openssl" x509 $x509hash -fingerprint -noout -in "$fname"`;
# ...
system ("cp", $fname, $hash);
# ...
open IN, $fname;
```

Both versions contain:
- Backtick shell execution with filename interpolation (command injection via filenames)
- `system("cp", ...)` calls (though this list-form is safer, the backtick calls are not)
- Two-argument `open` (vulnerable to Perl open-mode injection)

The FIPS version is simpler (fewer features) but has the **same fundamental vulnerability
patterns**. Both use backtick execution with `$fname` embedded in shell commands, which is
the core command injection vector.

### Verdict: **GT_ERROR**

The c_rehash script has had shell injection vulnerabilities since its inception. The
vulnerable backtick execution and unsafe file operations exist in OpenSSL-fips-1_2_0 (2007)
just as they do in OpenSSL_1_0_2 (2015). The GT range starting at OpenSSL_1_0_2 is too
narrow; the vulnerability predates it by at least 8 years.

---

## CVE-2021-33193 (httpd) -- WRONG_CONTEXT

| Field | Value |
|-------|-------|
| Our finding | VULN at `1.3.9` |
| GT start | `2.4.17` |
| Distance | -137 tags |
| CWE | None listed (HTTP/2 request smuggling) |
| Fixing commit | `ecebcc035ccd8d0e2984fe41420d9e944f456b3c` |

### What the fix does

The fix refactors `server/protocol.c` to split `ap_read_request()` into separate functions:
`ap_create_request()`, `ap_parse_request_line()`, and `ap_check_request_header()`. It adds
request-target validation per RFC 7230 section 5.3, and modifies how the HTTP/2 module
(`h2_request.c`) processes requests to use the shared parsing functions instead of its own
implementation.

### Code comparison

**Apache 1.3.9**: This version does not have `server/protocol.c` at all. The server directory
contains only `buildmark.c`, `config.c`, `gen_test_char.c`, `gen_uri_delims.c`, `log.c`,
`main.c`, `rfc1413.c`, `util.c`, `util_date.c`, `util_md5.c`, `util_script.c`, `util_uri.c`,
and `vhost.c`. There is no HTTP/2 module (`modules/http2/` does not exist). The 1.3.x
architecture is fundamentally different from 2.4.x.

**Apache 2.4.17**: Has `server/protocol.c` with `ap_read_request()`, `read_request_line()`,
`ap_parse_uri()`, and the HTTP/2 module at `modules/http2/h2_request.c`.

### Verdict: **WRONG_CONTEXT**

Apache 1.3.9 is an entirely different major version with a fundamentally different codebase.
The vulnerable file (`server/protocol.c`) does not exist, and HTTP/2 support (the attack
vector for CVE-2021-33193) was not added until Apache 2.4.x. Our tool likely matched some
superficial code pattern in a different file (possibly `server/config.c` or similar) that
has no semantic relationship to the actual vulnerability. This is a clear false positive
from matching across incompatible major versions.

---

## CVE-2024-2466 (curl) -- WRONG_CONTEXT

| Field | Value |
|-------|-------|
| Our finding | VULN at `curl-7_70_0` |
| GT start | `curl-8_5_0` |
| Distance | -62 tags |
| CWE | CWE-297 (Improper Validation of Certificate with Host Mismatch) |
| Fixing commit | `3d0fd382a29b95561b90b7ea3e7eb04dfdd43538` |

### What the fix does

The fix changes `lib/vtls/mbedtls.c` to call `mbedtls_ssl_set_hostname()` unconditionally
(with `connssl->peer.sni ? connssl->peer.sni : connssl->peer.hostname`), instead of only
when `connssl->peer.sni` is non-NULL. When SNI is NULL (e.g., connecting to an IP address),
the previous code skipped `mbedtls_ssl_set_hostname()` entirely, which meant CN/SAN
certificate verification was bypassed.

### Code comparison

**curl-7_70_0** (`lib/vtls/mbedtls.c` line 476):
```c
if(mbedtls_ssl_set_hostname(&backend->ssl, hostname)) {
    failf(data, "couldn't set hostname in mbedTLS");
    return CURLE_SSL_CONNECT_ERROR;
}
```
Called **unconditionally**. Certificate verification always happens.

**curl-8_5_0** (`lib/vtls/mbedtls.c` lines 643-651):
```c
if(connssl->peer.sni) {
    if(mbedtls_ssl_set_hostname(&backend->ssl, connssl->peer.sni)) {
        failf(data, "Failed to set SNI");
        return CURLE_SSL_CONNECT_ERROR;
    }
}
```
Called **only when `connssl->peer.sni` is non-NULL**. When SNI is NULL (IP address connections),
certificate verification is skipped.

The vulnerable conditional guard (`if(connssl->peer.sni)`) was introduced by commit
`fa714830e9` ("vtls/vquic, keep peer name information together", 2023-11-17), which
refactored the SNI handling. This commit first appears in curl-8_5_0 (confirmed by
`git merge-base --is-ancestor`).

### Verdict: **WRONG_CONTEXT**

In curl-7_70_0, `mbedtls_ssl_set_hostname()` is called unconditionally, meaning certificate
host verification always occurs. The vulnerability was introduced by a later refactoring
(commit `fa714830e9`) that wrapped the call in a conditional, first appearing in curl-8_5_0.
Our tool matched the presence of the `mbedtls_ssl_set_hostname` call, but in curl-7_70_0 the
call is actually **correct** (unconditional), not vulnerable. The vulnerable pattern is the
**absence** of the call when SNI is NULL, which only occurs in newer versions.

---

## Summary

| CVE | Repo | Early Version | GT Start | Classification | Explanation |
|-----|------|---------------|----------|----------------|-------------|
| CVE-2023-38039 | curl | curl-7_20_0 | curl-7_84_0 | **GT_ERROR** | No header size limit exists in either version; vulnerability is identical |
| CVE-2023-38545 | curl | curl-7_21_7 | curl-7_69_0 | **WRONG_CONTEXT** | Synchronous code handles fallback correctly; bug is in state machine introduced at 7_69_0 |
| CVE-2022-2068 | openssl | OpenSSL-fips-1_2_0 | OpenSSL_1_0_2 | **GT_ERROR** | Shell injection in c_rehash exists since script inception (2007) |
| CVE-2021-33193 | httpd | 1.3.9 | 2.4.17 | **WRONG_CONTEXT** | Apache 1.3.x has no protocol.c, no HTTP/2 module; entirely different codebase |
| CVE-2024-2466 | curl | curl-7_70_0 | curl-8_5_0 | **WRONG_CONTEXT** | mbedtls_ssl_set_hostname called unconditionally in 7_70_0 (safe); vulnerability is conditional guard added later |

### Key Findings

**2 out of 5 are genuine GT errors** (CVE-2023-38039, CVE-2022-2068):
- These represent cases where the vulnerability truly existed much earlier than the advisory/GT claims.
- For CVE-2023-38039, the unbounded header accumulation has been present since at least curl-7_20_0.
- For CVE-2022-2068, the c_rehash shell injection has existed since the script was written (2007).

**3 out of 5 are tool false positives** (CVE-2023-38545, CVE-2021-33193, CVE-2024-2466):
- CVE-2023-38545: The tool cannot distinguish synchronous (safe) vs state-machine (buggy) control flow.
- CVE-2021-33193: The tool matched code across incompatible major versions (Apache 1.3 vs 2.4).
- CVE-2024-2466: The tool matched the presence of a function call but missed that the vulnerability
  is the *conditional wrapping* (absence of the call), not the call itself.

### Implications for Tool Improvement

1. **State machine / control flow analysis**: The SOCKS5 case shows that syntactic code matching
   cannot capture semantic differences in control flow. A synchronous function with a flag works
   correctly; the same flag in a state machine does not.

2. **Cross-version validation**: The httpd case shows the tool needs awareness of major version
   boundaries. Apache 1.3.x and 2.4.x share a repository but are fundamentally different codebases.

3. **Negative patterns**: The mbedtls case shows the tool needs to detect *absence* of code
   (a missing function call) rather than just *presence*. The vulnerability is a conditional guard
   that prevents a function from being called, not the function call itself.


---

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
