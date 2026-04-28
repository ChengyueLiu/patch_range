# Root Cause Analysis: SAFE Cases with Large Distance

When our tool classifies a version as VULN, but the earliest ground-truth affected
version is much older, the "distance" (number of versions between GT start and our
found version) reveals how much of the vulnerable range we miss. This document
examines 4 such cases in detail.

## Tool Mechanism Recap

The classifier (`pipeline/vuln_classifier.py`) works by:
1. Extracting deleted lines from the fixing commit diff
2. Normalizing whitespace/operators for comparison
3. Locating the code region via context lines from the hunk
4. Checking if normalized deleted lines exist within that region

This is fundamentally a **textual matching** approach. The vulnerability is flagged
only when the exact (normalized) text of the deleted lines exists in the file.

---

## CVE-2020-35965 (FFmpeg) -- Distance: 310 versions

**Vulnerability:** Out-of-bounds write in EXR decoder (`libavcodec/exr.c`).
The loop `for (y = 0; y < ymin; y++)` zeroes out lines at the start of the frame
buffer, but `ymin` is not capped at the image height `h`, so a crafted EXR file with
`ymin > h` causes writes past the allocated buffer.

**Fix (commit 3e5959b345):** Changes the loop bound from `s->ymin` to
`FFMIN(s->ymin, s->h)`.

**Deleted line from the fix:**
```c
for (y = 0; y < s->ymin; y++) {
```

**Code at GT earliest version (n0.11):**
```c
// Zero out the start if ymin is not 0
for (y = 0; y < ymin; y++) {
    memset(ptr, 0, avctx->width * 6);
    ptr += stride;
}
```
At n0.11, `ymin` is a **local variable** in `decode_frame()`. The same unbounded loop
exists, but the text reads `ymin` not `s->ymin`.

**Code at tool-found version (n4.3):**
```c
// Zero out the start if ymin is not 0
for (i = 0; i < planes; i++) {
    ptr = picture->data[i];
    for (y = 0; y < s->ymin; y++) {
        memset(ptr, 0, out_line_size);
        ptr += picture->linesize[i];
    }
}
```
At n4.3, `ymin` is a **struct member** `s->ymin`. The EXR decoder was rewritten in
commit 38389058c3 (n2.3) moving from local variables to a decoder context struct.
The line `for (y = 0; y < s->ymin; y++)` first appears at n2.3.

**Why the tool misses n0.11 through n2.2:**
The deleted line from the patch is `for (y = 0; y < s->ymin; y++)`. At n0.11 the code
reads `for (y = 0; y < ymin; y++)`. After normalization, `s->ymin` != `ymin` -- the
struct member prefix `s->` is a textual difference that prevents matching.

Additionally, the surrounding context lines from the n4.3 hunk (multi-plane loop,
`picture->data[i]`, `out_line_size`) do not exist at n0.11, where the code is a
simpler single-plane implementation (`ptr = p->data[0]`, `avctx->width * 6`).

**What connects n0.11 to the vulnerability:**
The semantic pattern is identical: an unbounded loop using `ymin` as the upper bound
without capping at image height. The validation check `ymax >= h` is present at both
versions but does NOT protect against `ymin >= h` (only `ymin > ymax` is checked).

**What an LLM would need:**
- Understand that `ymin` (local) and `s->ymin` (struct member) are the same logical
  value -- both parsed from the EXR file header via `bytestream_get_le32`
- Recognize that the vulnerability pattern is "loop bounded by untrusted value without
  capping at buffer size" regardless of variable naming
- Check whether the validation logic (`xmin > xmax || ymin > ymax || ... || ymax >= h`)
  prevents `ymin >= h` -- it does NOT, since `ymin < ymax < h` can still have `ymin`
  large enough to cause excessive writes

---

## CVE-2020-12829 (QEMU) -- Distance: 71 versions

**Vulnerability:** Integer overflow in sm501 2D engine (`hw/display/sm501.c` at later
versions, `hw/sm501.c` at v0.13.0). The FILL_RECT and COPY_AREA macros compute an
index as `((dst_y + y) * pitch + dst_x + x) * bpp` using signed `int` arithmetic,
which can overflow when a malicious guest provides large coordinates. No bounds
checking prevents writes outside the local memory buffer.

**Fix (commit b15a22bbcb):** Complete rewrite replacing hand-written COPY_AREA/FILL_RECT
macros with pixman library calls, changing `int` to `unsigned int` for dimensions, and
adding explicit bounds checking (`dst_base + ... >= get_local_mem_size(s)`).

**Key deleted lines from fix (pre-fix code at ~v5.1.0):**
```c
int dst_x = (s->twoD_destination >> 16) & 0x01FFF;
int dst_y = s->twoD_destination & 0xFFFF;
int width = (s->twoD_dimension >> 16) & 0x1FFF;
int height = s->twoD_dimension & 0xFFFF;
...
int dst_pitch = (s->twoD_pitch >> 16) & 0x1FFF;
...
#define FILL_RECT(_bpp, _pixel_type) { \
    int y, x; \
    for (y = 0; y < height; y++) { \
        for (x = 0; x < width; x++) { \
            int index = ((dst_y + y) * dst_pitch + dst_x + x) * _bpp; \
```

**Code at GT earliest version (v0.13.0) -- file `hw/sm501.c`:**
```c
int dst_x = (s->twoD_destination >> 16) & 0x01FFF;
int dst_y = s->twoD_destination & 0xFFFF;
int operation_width = (s->twoD_dimension >> 16) & 0x1FFF;
int operation_height = s->twoD_dimension & 0xFFFF;
...
int dst_width = (s->dc_crt_h_total & 0x00000FFF) + 1;
...
#define FILL_RECT(_bpp, _pixel_type) { \
    int y, x; \
    for (y = 0; y < operation_height; y++) { \
        for (x = 0; x < operation_width; x++) { \
            int index = ((dst_y + y) * dst_width + dst_x + x) * _bpp; \
```

**Code at tool-found version (v2.10.0) -- file `hw/display/sm501.c`:**
Same as v0.13.0 in structure: uses `operation_width`, `operation_height`, `dst_width`.
The file was moved to `hw/display/sm501.c` at some point, but variable names remained
unchanged until commit 6f8183b5dc (v5.1.0) which renamed them to `width`, `height`,
`dst_pitch`.

**Why the tool misses v0.13.0 through v2.10.0 (and likely v2.10.0 itself is a
borderline match):**
Multiple layers of textual mismatch:

1. **Variable names:** The fix deletes `int width = ...` but v0.13.0 has
   `int operation_width = ...`. Similarly `height` vs `operation_height`,
   `dst_pitch` vs `dst_width`.

2. **File path:** The fix targets `hw/display/sm501.c`, but at v0.13.0 the file
   is `hw/sm501.c`.

3. **Macro body differences:** The FILL_RECT macro uses `dst_pitch` in the fix
   but `dst_width` in v0.13.0/v2.10.0. Even the index computation formula differs:
   `dst_pitch + dst_x` vs `dst_width + dst_x`.

4. **Missing functionality:** At v0.13.0, only FILL_RECT exists (no COPY_AREA).
   The fix deletes both. A tool matching COPY_AREA deleted lines would find nothing.

Note: The tool finding VULN at v2.10.0 despite these differences suggests it may be
matching on lines that are common across all versions (like `int dst_x = ...` or
`FILL_RECT(1, uint8_t);`), or the context-free fallback path is triggering.

**What connects v0.13.0 to the vulnerability:**
- Same integer types (`int`) for all dimension/coordinate variables
- Same lack of bounds checking on computed index
- Same macro pattern with unchecked arithmetic: `((dst_y + y) * pitch + dst_x + x) * bpp`
- The bitmask extractions are identical: `(s->twoD_dimension >> 16) & 0x1FFF`

**What an LLM would need:**
- Recognize that `operation_width` and `width` are the same value (same register,
  same bitmask) -- a simple rename
- Understand that `dst_width` (from `dc_crt_h_total`) and `dst_pitch` (from
  `twoD_pitch >> 16`) are different values but serve the same role, and both lack
  overflow protection
- Identify the vulnerability as "signed integer arithmetic on guest-controlled values
  used as memory index without bounds checking" -- a pattern present regardless of
  variable names

---

## CVE-2023-27538 (curl) -- Distance: 131 versions

**Vulnerability:** SSH connection reuse allows using a different set of credentials
than intended. When reusing connections, the SSH-specific configuration (key files)
is not properly compared.

**Fix (commit af369db4d3):** Changes `==` to `&` in the PROTO_FAMILY_SSH check:
```c
-      if(get_protocol_family(needle->handler) == PROTO_FAMILY_SSH) {
+      if(get_protocol_family(needle->handler) & PROTO_FAMILY_SSH) {
```

**Deleted line:** `if(get_protocol_family(needle->handler) == PROTO_FAMILY_SSH) {`

This line, and the `ssh_config_matches()` function it gates, were introduced in
commit 1645e9b445 as a fix for CVE-2022-27782, first appearing in curl-7_83_1.

**Code at GT earliest version (curl-7_16_1):**
The `ConnectionExists()` function at curl-7_16_1 has NO SSH-specific reuse check at
all. Connections are reused based solely on protocol string, hostname, and port:
```c
if(strequal(needle->protostr, check->protostr) &&
   strequal(needle->host.name, check->host.name) &&
   (needle->remote_port == check->remote_port) ) {
    // SSL config check for SSL connections
    // user/password check for FTP and HTTP+NTLM
    // but NO check for SSH credentials
    match = TRUE;
}
```

**Code at tool-found version (curl-7_88_0):**
```c
if(get_protocol_family(needle->handler) == PROTO_FAMILY_SSH) {
    if(!ssh_config_matches(needle, check))
        continue;
}
```

**Why the tool misses curl-7_16_1 through curl-7_83_0:**
The deleted line `if(get_protocol_family(needle->handler) == PROTO_FAMILY_SSH)` simply
does not exist before curl-7_83_1. The entire concept of `PROTO_FAMILY_SSH`,
`get_protocol_family()`, and `ssh_config_matches()` did not exist yet.

This is a **category (c) case: the feature didn't exist yet.** The specific code that
the fix patches was itself a fix for an earlier CVE (CVE-2022-27782), but it introduced
a new bug (using `==` instead of `&`).

**However**, the GT says curl-7_16_1 is affected. This is because the **fundamental
vulnerability** (SSH connections reused without checking SSH-specific credentials)
existed from the very beginning of SSH support (curl-7_16_1). The fix for
CVE-2022-27782 attempted to address this, but the `==` vs `&` bug meant the fix was
incomplete, so the original vulnerability persisted.

**What connects curl-7_16_1 to the vulnerability:**
- SSH connections can be reused (SCP/SFTP support exists since curl-7_16_1)
- No SSH-specific credential comparison in connection reuse logic
- The same fundamental security property is violated: "reused connections must have
  matching credentials"

**What an LLM would need:**
- Understand that the vulnerability is about a MISSING check, not a wrong check
- Recognize that the absence of `ssh_config_matches()` is MORE vulnerable than a
  buggy implementation of it
- This requires reasoning about the security property ("SSH connections should not be
  reused across different credential sets") rather than looking for specific code text
- Understand the CVE lineage: CVE-2022-27782 added the check, CVE-2023-27538 fixed
  the check -- but both CVEs cover the same underlying vulnerability surface

---

## CVE-2024-8096 (curl) -- Distance: 62 versions

**Vulnerability:** OCSP stapling verification in GnuTLS backend (`lib/vtls/gtls.c`)
can be bypassed. The code wraps all OCSP response validation inside
`if(gnutls_ocsp_status_request_is_checked(session, 0) == 0)`, meaning it only
performs manual OCSP verification when GnuTLS says it has NOT already checked the
status. If GnuTLS reports it has checked (returns non-zero), the code skips its own
validation entirely -- trusting GnuTLS even when GnuTLS may not actually have properly
verified the OCSP response.

**Fix (commit aeb1a281ca):** Removes the `gnutls_ocsp_status_request_is_checked` gate.
The OCSP response is now always fetched and validated manually. Also adds
`GNUTLS_NO_STATUS_REQUEST` init flag support.

**Key deleted line:**
```c
if(gnutls_ocsp_status_request_is_checked(session, 0) == 0) {
```

**Code at GT earliest version (curl-7_41_0):**
```c
#ifdef HAS_OCSP
if(data->set.ssl.verifystatus) {
    if(gnutls_ocsp_status_request_is_checked(session, 0) == 0) {
        if(verify_status & GNUTLS_CERT_REVOKED)
            failf(data, "SSL server certificate was REVOKED\n");
        else
            failf(data, "SSL server certificate status verification FAILED");
        return CURLE_SSL_INVALIDCERTSTATUS;
    }
    else
        infof(data, "SSL server certificate status verification OK\n");
}
```
The `gnutls_ocsp_status_request_is_checked` call was added in commit f13669a375
which first appears in curl-7_41_0. This is exactly the GT earliest version.

**Code at tool-found version (curl-7_78_0):**
```c
if(SSL_CONN_CONFIG(verifystatus)) {
    if(gnutls_ocsp_status_request_is_checked(session, 0) == 0) {
        gnutls_datum_t status_request;
        gnutls_ocsp_resp_t ocsp_resp;
        gnutls_ocsp_cert_status_t status;
        gnutls_x509_crl_reason_t reason;
        rc = gnutls_ocsp_status_request_get(session, &status_request);
        ...
```

**Why the tool misses curl-7_41_0 through curl-7_42_1:**
The core deleted line `if(gnutls_ocsp_status_request_is_checked(session, 0) == 0) {`
is present at ALL versions from curl-7_41_0 onward. However, the **context lines**
from the fix diff (which come from the post-curl-7_43_0 expanded OCSP validation code)
do NOT exist at curl-7_41_0.

At curl-7_41_0, the code inside the `is_checked == 0` block is a simple 5-line
check (`verify_status & GNUTLS_CERT_REVOKED`). Starting from curl-7_43_0 (commit
a5e09e9eea), this was expanded to the full `gnutls_ocsp_resp_get_single()` approach
with individual revocation reason handling.

The fix diff's context lines reference `gnutls_ocsp_resp_t ocsp_resp`, `status_request`,
and the switch/case on `GNUTLS_OCSP_CERT_GOOD` / `GNUTLS_OCSP_CERT_REVOKED` -- none
of which exist at curl-7_41_0. Without matching context, the tool cannot locate the
code region, and the single deleted line `if(gnutls_ocsp_status_request_is_checked...`
is probably insufficient for the fallback global match (which requires >= 2 matching
deleted lines per hunk).

**What connects curl-7_41_0 to the vulnerability:**
The exact same function call is the root cause at both versions:
`gnutls_ocsp_status_request_is_checked(session, 0) == 0` is used as a gate to skip
manual OCSP validation. Whether the manual validation is simple (curl-7_41_0) or
detailed (curl-7_43_0+), the gate is the same problem.

**What an LLM would need:**
- Focus on the `gnutls_ocsp_status_request_is_checked` call as the vulnerability,
  not the detailed OCSP parsing code around it
- Understand that this function call appeared in curl-7_41_0 and persisted unchanged
  through all versions until the fix
- Recognize that surrounding code evolution (simple revocation check -> detailed
  response parsing) does not affect the vulnerability, which is purely about the
  gating condition

---

## Summary of Root Causes

| CVE | Root Cause Category | Why Tool Misses Early Versions |
|-----|-------------------|-------------------------------|
| CVE-2020-35965 | (a) Written differently | `ymin` (local) vs `s->ymin` (struct); surrounding code completely restructured |
| CVE-2020-12829 | (a) Written differently + (d) file moved | `operation_width`/`dst_width` vs `width`/`dst_pitch`; `hw/sm501.c` vs `hw/display/sm501.c` |
| CVE-2023-27538 | (c) Feature didn't exist | The specific buggy code (`== PROTO_FAMILY_SSH`) was itself a fix for CVE-2022-27782; before that, the check was entirely absent (which is MORE vulnerable) |
| CVE-2024-8096 | (a) Written differently (context) | The key deleted line exists at all affected versions, but context lines don't match due to code evolution around it |

## Key Insights

### 1. Textual Matching Fails on Semantic Equivalence
All four cases demonstrate that the same vulnerability can be expressed in textually
different code. Variable renames (QEMU), struct refactoring (FFmpeg), and code
evolution around a vulnerable pattern (curl OCSP) all break text-based matching while
preserving the vulnerability semantics.

### 2. Missing Code Can Be More Vulnerable Than Buggy Code
CVE-2023-27538 shows an important edge case: the GT's earliest affected version has
NO SSH credential checking at all, which is strictly MORE vulnerable than the later
buggy check the fix targets. A tool looking for the specific buggy line can never find
a version where the entire feature is absent.

### 3. Context Evolution vs Vulnerability Persistence
CVE-2024-8096 is the most "fixable" case. The vulnerable line
(`gnutls_ocsp_status_request_is_checked`) exists verbatim at ALL affected versions.
The tool misses it only because the surrounding context lines evolved. A more relaxed
context matching strategy (fewer required context lines, or matching the vulnerable
line itself as primary signal) could recover these cases.

### 4. Suggested Improvements
- **Semantic-aware matching:** For simple renames (QEMU, FFmpeg), extract the
  computation pattern (e.g., "register & mask as loop bound") rather than exact text
- **Missing-check detection:** For CVE-2023-27538-type cases, check whether the
  security-relevant check EXISTS rather than whether a specific buggy version of it
  exists
- **Relaxed context matching:** For CVE-2024-8096, allow matching when the key
  deleted line exists even if context lines don't (with appropriate confidence
  thresholds)
- **LLM-based semantic comparison:** Use an LLM to compare the code at the candidate
  version against the vulnerability description, rather than relying solely on textual
  diff matching
