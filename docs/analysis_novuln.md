# Analysis: Why Some CVEs Have No Meaningful Deleted Lines (NoVuln Cases)

## Background

The VARA pipeline identifies vulnerability-affected versions by tracing deleted lines
from the fixing patch backward through git history to find the vulnerability
introduction point. When a fixing patch has **zero meaningful deleted lines**, this
approach cannot work -- there is no "fingerprint" to search for. These are classified
as **NoVuln** cases.

A line is considered "trivial" (not meaningful) if it matches common generic patterns
like `}`, `else`, `return 0;`, `for (;;) {`, `goto err;`, etc. (defined in
`pipeline/line_filter.py`).

Across the 411-CVE benchmark (excluding linux), **93 CVEs (22.6%)** fall into the
NoVuln category. This document analyzes 5 representative cases to understand the
root causes and what alternative information an LLM would need.

---

## Taxonomy of NoVuln Root Causes

| Category | Description | Example Pattern |
|----------|-------------|-----------------|
| **(a) Pure add-only** | Fix only inserts new code; nothing is deleted | Adding a NULL/bounds check |
| **(b) Only trivial deletions** | Fix deletes lines, but all are generic syntax | Replacing `for(;;)` with `while(cond)` |
| **(c) Missing state reset** | Fix adds a single assignment that was absent | `lh->num_items = 0;` |
| **(d) Counter/limit addition** | Fix introduces a new counter variable and limit check | Adding `link_cnt` to cap iterations |

Categories (a), (c), and (d) are all subtypes of "add-only" fixes. Category (b) is
a "line modification" where the deleted portion is too generic to be useful.

---

## Case 1: CVE-2020-12284 -- FFmpeg

**Repo:** FFmpeg
**CWE:** CWE-787 (Out-of-bounds Write), CWE-20 (Improper Input Validation)
**Fixing commits:** `1812352d`, `838105153`, `a3a3730b` (3 commits, same fix on different branches)
**Affected versions:** n4.1 through n4.2.2

### Diff (identical across all 3 commits)

```diff
diff --git a/libavcodec/cbs_jpeg.c b/libavcodec/cbs_jpeg.c
index 6bbce5f89b..89512a26bb 100644
--- a/libavcodec/cbs_jpeg.c
+++ b/libavcodec/cbs_jpeg.c
@@ -197,6 +197,9 @@ static int cbs_jpeg_split_fragment(CodedBitstreamContext *ctx,
         if (marker == JPEG_MARKER_SOS) {
             length = AV_RB16(frag->data + start);

+            if (length > end - start)
+                return AVERROR_INVALIDDATA;
+
             data_ref = NULL;
             data     = av_malloc(end - start +
                                  AV_INPUT_BUFFER_PADDING_SIZE);
```

### Classification: **(a) Pure add-only -- missing bounds check**

Zero deleted lines. The fix adds a bounds check (`if (length > end - start)`) that
was simply absent. The vulnerability exists because `length` is read from untrusted
input (`AV_RB16(frag->data + start)`) and used without validation, leading to
out-of-bounds memory access.

### What an LLM would need

To determine if a version is affected, an LLM must:
1. Check if `libavcodec/cbs_jpeg.c` exists (file was added in commit `525de2000b`).
2. Find the `cbs_jpeg_split_fragment` function and the `JPEG_MARKER_SOS` handling block.
3. Check whether a bounds check on `length` vs `end - start` is present before the
   `av_malloc` call.

The vulnerability introduction coincides with the file's creation. Any version
containing `cbs_jpeg.c` without the bounds check is affected.

---

## Case 2: CVE-2022-1473 -- OpenSSL

**Repo:** openssl
**CWE:** CWE-459 (Incomplete Cleanup), CWE-404 (Improper Resource Shutdown)
**Fixing commit:** `64c85430f9`
**Affected versions:** OpenSSL_1_1_0 through openssl-3.0.2 (40 release tags)

### Diff

```diff
diff --git a/crypto/lhash/lhash.c b/crypto/lhash/lhash.c
index a15857cf9f..1cd988f01f 100644
--- a/crypto/lhash/lhash.c
+++ b/crypto/lhash/lhash.c
@@ -100,6 +100,8 @@ void OPENSSL_LH_flush(OPENSSL_LHASH *lh)
         }
         lh->b[i] = NULL;
     }
+
+    lh->num_items = 0;
 }
```

### Classification: **(c) Missing state reset -- omitted assignment**

Zero deleted lines. The `OPENSSL_LH_flush()` function frees all hash table entries
and sets bucket pointers to NULL, but forgets to reset `lh->num_items` to 0. This
causes subsequent operations to believe the table still has entries, leading to
memory not being properly reclaimed (CWE-459: Incomplete Cleanup).

The fix is a single line: `lh->num_items = 0;`.

### What an LLM would need

1. Find the `OPENSSL_LH_flush` function in `crypto/lhash/lhash.c`.
2. Examine whether `num_items` is reset to 0 after the flush loop completes.
3. The function was introduced around `OPENSSL_LH_*` rename (commit `726b329339`).
   Any version with `OPENSSL_LH_flush` that omits the `num_items = 0` reset is affected.

This is a semantic understanding problem: the LLM must reason that a "flush" function
should reset all state, including counters.

---

## Case 3: CVE-2021-4182 -- Wireshark

**Repo:** wireshark
**CWE:** CWE-835 (Loop with Unreachable Exit Condition)
**Fixing commit:** `b3215d99ca`
**Affected versions:** v2.9.0 through wireshark-3.6.0 (96 release tags)

### Diff

```diff
diff --git a/epan/dissectors/file-rfc7468.c b/epan/dissectors/file-rfc7468.c
--- a/epan/dissectors/file-rfc7468.c
+++ b/epan/dissectors/file-rfc7468.c
@@ -150,7 +150,7 @@
-    for (;;) {
+    while (tvb_offset_exists(tvb, offset)) {
         linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
...
@@ -212,7 +212,7 @@
-    for (;;) {
+    while (tvb_offset_exists(tvb, offset)) {
         linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
...
@@ -257,7 +257,7 @@
-    for (;;) {
+    while (tvb_offset_exists(tvb, offset)) {
         linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
```

### Classification: **(b) Only trivial deletions -- line modification with generic deleted portion**

Three lines are deleted, but all are `for (;;) {` -- a pattern that appears
ubiquitously in C code and is in the trivial-lines filter. The actual fix replaces
infinite loops with bounded `while (tvb_offset_exists(tvb, offset))` loops. The
deleted line (`for (;;)`) carries zero vulnerability-specific information.

This is a *line modification* (delete+add), but the deleted side is too generic
to serve as a vulnerability fingerprint. The meaningful information is entirely
in the *added* replacement.

### What an LLM would need

1. Find `dissect_rfc7468` in `epan/dissectors/file-rfc7468.c`.
2. Check whether the three loop constructs use `for (;;)` (vulnerable -- no bounds
   on tvb access) or `while (tvb_offset_exists(tvb, offset))` (fixed).
3. A version is affected if `file-rfc7468.c` exists and uses unbounded `for (;;)`
   loops in the dissect function.

The LLM must understand that `for (;;)` combined with `tvb_find_line_end` can loop
infinitely on malformed input, while the bounded while-loop prevents this.

---

## Case 4: CVE-2021-44790 -- Apache httpd

**Repo:** httpd
**CWE:** CWE-787 (Out-of-bounds Write)
**Fixing commit:** `e1a199e8fd`
**Affected versions:** 2.4.51

### Diff

```diff
diff --git a/modules/lua/lua_request.c b/modules/lua/lua_request.c
index 5c9a496d68..80fe9fe97e 100644
--- a/modules/lua/lua_request.c
+++ b/modules/lua/lua_request.c
@@ -410,6 +410,7 @@ static int req_parsebody(lua_State *L)
             if (end == NULL) break;
             key = (char *) apr_pcalloc(r->pool, 256);
             filename = (char *) apr_pcalloc(r->pool, 256);
+            if (end - crlf <= 8) break;
             vlen = end - crlf - 8;
             buffer = (char *) apr_pcalloc(r->pool, vlen+1);
             memcpy(buffer, crlf + 4, vlen);
```

### Classification: **(a) Pure add-only -- missing bounds check**

Zero deleted lines. The fix adds `if (end - crlf <= 8) break;` to prevent a
negative/underflow in `vlen = end - crlf - 8`. Without this check, when
`end - crlf` is less than 8, `vlen` underflows (unsigned arithmetic), causing
a massive `memcpy` that writes out of bounds.

The vulnerable code path is in `req_parsebody`, the multipart form data parser
in mod_lua. The vulnerable pattern (`vlen = end - crlf - 8` without validation)
was introduced in commit `1a50285096`.

### What an LLM would need

1. Find `req_parsebody` in `modules/lua/lua_request.c`.
2. Locate the line `vlen = end - crlf - 8`.
3. Check whether a guard `if (end - crlf <= 8) break;` (or equivalent) precedes it.
4. Any version containing the unguarded subtraction is affected.

This is another classic "missing input validation" add-only fix. The LLM needs
to understand integer underflow: if `end - crlf < 8`, the subtraction wraps.

---

## Case 5: CVE-2020-14394 -- QEMU

**Repo:** qemu
**CWE:** CWE-835 (Loop with Unreachable Exit Condition)
**Fixing commit:** `05f43d44e4`
**Affected versions:** v1.1.0 through v2.7.1 (44 release tags)

### Diff

```diff
diff --git a/hw/usb/hcd-xhci.c b/hw/usb/hcd-xhci.c
index 726435c462..ee4fa484d6 100644
--- a/hw/usb/hcd-xhci.c
+++ b/hw/usb/hcd-xhci.c
@@ -54,6 +54,8 @@
+#define TRB_LINK_LIMIT  4
+
@@ -1000,6 +1002,7 @@ static TRBType xhci_ring_fetch(...)
     PCIDevice *pci_dev = PCI_DEVICE(xhci);
+    uint32_t link_cnt = 0;

     while (1) {
@@ -1026,6 +1029,9 @@
         } else {
+            if (++link_cnt > TRB_LINK_LIMIT) {
+                return 0;
+            }
             ring->dequeue = xhci_mask64(trb->parameter);
@@ -1043,6 +1049,7 @@ static int xhci_ring_chain_length(...)
+    uint32_t link_cnt = 0;

     while (1) {
@@ -1058,6 +1065,9 @@
         if (type == TR_LINK) {
+            if (++link_cnt > TRB_LINK_LIMIT) {
+                return -length;
+            }
```

### Classification: **(d) Counter/limit addition -- adding iteration bounds to prevent infinite loop**

Zero deleted lines. The fix introduces:
1. A new `#define TRB_LINK_LIMIT 4` constant.
2. A `uint32_t link_cnt` counter variable in two functions.
3. Checks `if (++link_cnt > TRB_LINK_LIMIT)` to break out of `while(1)` loops
   that follow TRB link chains.

Without these limits, a malicious guest can craft a circular TRB link chain that
causes the host QEMU process to loop infinitely (DoS). The fix adds entirely new
code -- there is nothing to delete because the limitation mechanism never existed.

### What an LLM would need

1. Find `xhci_ring_fetch` and `xhci_ring_chain_length` in `hw/usb/hcd-xhci.c`.
2. Check whether TRB_LINK processing has a loop counter / iteration limit.
3. The vulnerability exists in every version since the xHCI controller was
   implemented (originally as `hw/usb/hcd-xhci.c` from commit `f1ae32a1ec`).
4. Any version without a link traversal limit in these functions is affected.

The LLM must understand that following guest-controlled linked structures without
bounds leads to infinite loops.

---

## Summary Table

| CVE | Repo | Category | Deleted Lines | Fix Pattern | Introduction Signal |
|-----|------|----------|---------------|-------------|-------------------|
| CVE-2020-12284 | FFmpeg | (a) Pure add-only | 0 | Add bounds check before allocation | File creation (`cbs_jpeg.c`) |
| CVE-2022-1473 | OpenSSL | (c) Missing state reset | 0 | Add `num_items = 0` after flush | Function creation (`OPENSSL_LH_flush`) |
| CVE-2021-4182 | Wireshark | (b) Trivial deletions | 3 (`for (;;) {`) | Replace unbounded loop with bounded | File creation (`file-rfc7468.c`) |
| CVE-2021-44790 | httpd | (a) Pure add-only | 0 | Add underflow guard before subtraction | Feature introduction (`req_parsebody`) |
| CVE-2020-14394 | QEMU | (d) Counter/limit add | 0 | Add iteration counter and limit | Function creation (`xhci_ring_fetch`) |

---

## Key Observations

### 1. All NoVuln fixes share a common theme: adding what was never there

Unlike typical vulnerability fixes that *correct* existing code (modify a comparison,
fix a calculation), NoVuln fixes *introduce* entirely new defensive logic. The
vulnerability is not "the code does X wrong" but "the code fails to do Y at all."

### 2. Vulnerability introduction often coincides with feature creation

In 4 of 5 cases, the vulnerability was introduced when the feature/function was
first written. The code was "born vulnerable" -- the developer simply did not
anticipate the attack scenario. This means the introduction point is typically
the commit that added the file or function, not a later regression.

### 3. The meaningful signal is in the ADDED lines and their context

For an LLM-based approach to handle NoVuln cases, it must:
- Understand what the added code *prevents* (bounds check, counter limit, state reset)
- Identify the *vulnerable pattern* by reading the surrounding context (e.g.,
  `vlen = end - crlf - 8` without a guard is the vulnerability)
- Check each historical version for whether that pattern exists *without* the fix

### 4. Context-based vulnerability signatures

Instead of deleted-line fingerprints, NoVuln cases require **contextual signatures**:

| Fix Type | Signature Strategy |
|----------|-------------------|
| Missing bounds check | Look for the unguarded operation (e.g., `vlen = end - crlf - 8` without preceding size check) |
| Missing state reset | Look for the function that omits the reset (e.g., `OPENSSL_LH_flush` without `num_items = 0`) |
| Missing loop bound | Look for unbounded loops processing external data (e.g., `while(1)` following TRB links) |
| Loop condition fix | Look for the old loop form (e.g., `for (;;)` instead of `while (tvb_offset_exists(...))`) |

### 5. Implications for tooling

The current deleted-line tracing approach fundamentally cannot handle these cases.
Alternative strategies include:
- **Added-line context matching:** Use the lines surrounding the addition as a
  fingerprint. If the context exists but the added check does not, the version
  is vulnerable.
- **Function-level analysis:** Check if the function/file exists. If the fix adds
  a check to a function, any version with that function but without the check is
  affected.
- **LLM semantic analysis:** Present the patch and the version's source code to an
  LLM and ask it to determine if the vulnerability pattern is present.
