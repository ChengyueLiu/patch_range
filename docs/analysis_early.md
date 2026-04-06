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
