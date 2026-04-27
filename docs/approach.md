# VARA 方法论

## 核心思路

**先确定一个保证不漏的候选范围，再精确定位漏洞引入的起点。**

## 为什么现有方法不行

现有方法分两类，都在追求精度的同时限制了召回：

**Matching**：从 patch 提取特征，去每个版本里找是否存在。为了不误报，匹配条件设得很严（精确 hash、完全一致的 token）。结果：代码稍有变化就匹配不上，漏报。

**Tracing**：从 fixing commit 用 git blame 回溯找引入漏洞的 commit，推断中间版本受影响。为了不追错，大多数工具只做单步 blame、选最保守的 commit。结果：追溯不到位，范围偏小，漏报。

两种方法的最佳 F1 都不超过 78%，核心原因是**它们试图一步到位同时解决召回和精度**。

## 我们的方案

分两个阶段：先建立可靠的候选范围（保证不漏），再在候选范围内精确定位。

### 阶段一：建立可靠的候选范围

通过三层操作，逐步缩小范围，每一层都保证不漏。

#### 第一层：确定最大候选范围

**原理**：漏洞存在于代码中。相关代码不存在的版本不可能有漏洞。因此，从相关代码第一次出现到补丁应用之间的所有版本构成最大候选范围。

**操作**：

对每个 release tag，用 `git grep` 检查漏洞代码（patch 中的 deleted lines）是否存在于该版本的代码树中。存在则纳入候选范围。然后排除包含 fixing commit 的版本。

**关键设计决策及演进**：

实验过程中发现了八个影响 Layer 1 正确性和性能的关键问题，逐步驱动了方案的演进：

**发现 1：跨文件代码迁移**。实际项目中代码经常从一个文件迁移到另一个文件（函数拆分、模块重构）。例如 curl 项目中 `lib/ssh.c` 的 SCP 路径处理代码迁移到 `lib/curl_path.c`，`lib/url.c` 的选项设置代码迁移到 `lib/setopt.c`。`git log --follow` 只能追踪文件级重命名（`git mv`），`git blame -C` 在代码被修改后也无法穿透。仅用文件追溯导致 curl 项目 6 个 CVE 漏报 282 个 GT 版本。

**发现 2：`git log -S` 性能瓶颈**。`git log -S` 通过搜索代码模式首次出现的 commit 能解决跨文件问题，但需要遍历仓库每一个 commit 的 diff，单次调用在 openssl 上需要 10-25 秒，不可接受。

**发现 3（解决 1 和 2）：定向跨文件检测**。不需要全量搜索。对每个 patched file，先用 `git log --follow`（快速）找到文件引入 commit，然后在该 commit 的 parent 上做一次 `git grep` 检查代码是否在其他文件中已存在。如果存在，说明发生了跨文件迁移，再对旧文件做 `git log --follow`。总共只需 2-3 次 git 调用，总耗时 <1 秒，而 `git log -S` 需要 10-25 秒。

**发现 4：多分支独立引入同一文件**。`git log --follow` 只追踪当前分支（HEAD）的历史。对于多分支并行维护的项目（如 httpd 的 2.4.x 和 trunk），同一文件可能在不同分支上被独立引入（不同的 add commit）。`git log --follow` 只能找到其中一个分支的引入 commit，导致另一个分支的版本全部漏报。例如 httpd 的 `mod_proxy_uwsgi.c` 在 trunk 由 commit A 引入，在 2.4.x 由 commit B 独立引入。`git log --follow` 只找到 A，`git tag --contains A` 不包含 2.4.x 的任何 tag，导致 19 个 GT 版本全部漏报。解决方案：使用 `git log --all` 搜索所有分支上的文件引入 commit。

**发现 5：多个 fixing commit 的部分修复**。一个 CVE 可能有多个 fixing commit，每个修复漏洞的不同方面。如果某个版本只包含了部分 fixing commit，漏洞仍然存在。但我们的代码用 `减去包含任意一个 fix commit 的 tag` 来排除已修复版本，导致只包含部分修复的版本被错误排除。例如 FFmpeg CVE-2022-48434 有两个 fixing commit，版本 n4.4.3 包含了 commit 1 但不包含 commit 2，GT 标记为仍受影响，但我们错误地排除了它。解决方案：只排除包含**所有** fixing commit 的版本。

**发现 6：链式跨文件迁移**。代码可能经历多次文件迁移（A.c → B.c → C.c）。一层跨文件检测只能追溯到 B.c，漏掉最早的 A.c。例如 openjpeg 的 `codec/image_to_j2k.c` → `src/bin/jp2/image_to_j2k.c` → `src/bin/jp2/opj_compress.c`。解决方案：递归跨文件追溯，最大深度 3 层。

**发现 7：文件拆分不被 git 识别为 "Add"**。当一个大文件被拆分成多个小文件时（如 FFmpeg 的 `ffmpeg.c` 拆分出 `ffmpeg_opt.c`），git 内部记录为 "Modify" 而非 "Add"。`git log --diff-filter=A` 搜不到这种文件的创建 commit，导致追溯失败。例如 FFmpeg CVE-2020-20451 涉及 `ffmpeg_opt.c`，该文件有 310 个 commit 修改过但 `--diff-filter=A` 返回空。解决方案：当 `--diff-filter=A` 无结果时，用 `git log --reverse -1` 找到最早涉及该文件的 commit 作为兜底。

**发现 8：Benchmark 数据质量问题**。评估过程中发现 benchmark 自身存在三类标注错误：(1) 引用仓库中不存在的 tag。curl 项目有 37 个 GT tag（curl-4_x, curl-5_x 等早期版本）在公开仓库中不存在，任何工具都无法分析；(2) 已修复版本被标记为受影响。wireshark CVE-2021-4185（72 个版本）和 FFmpeg CVE-2020-22054（196 个版本）已包含修复代码但 GT 标记为受影响；(3) 标注一致性问题，论文自述 11.9% 的标注存在不一致（Cohen's Kappa 0.83）。我们构建了修正版 dataset（Dataset_amended.json），基于代码证据进行可复现的修正。

### 已知遗留问题

以下问题已识别但暂未修复，不影响整体方法的有效性：

1. **Add-only patch + 文件重命名**：当 fix 只新增代码（无 deleted lines），且文件被重命名过（如 FFmpeg 的 `ffmpeg.c` → `fftools/ffmpeg.c`），跨文件检测缺少搜索特征（无 deleted lines 可 grep），导致旧路径版本漏报。影响 FFmpeg CVE-2020-22042 等少量 CVE。可通过在 Layer 1 中对文件名做路径回退搜索解决。

2. **openjpeg 早期版本代码差异**：openjpeg 1.x 和 2.x 的代码结构差异极大，函数名、变量名、文件组织完全不同。跨文件检测的 token 搜索无法匹配。影响 CVE-2020-27845 等。属于代码重写场景的边界 case。

```
v1.0 --- v1.1 --- v1.2 --- v2.0 --- v2.1 --- v2.2 --- v3.0 --- v3.1
          ^                  \                                    ^
          |                   v2.3 --- v2.4 --- v2.5 --- v2.6    |
      代码首次引入                                ^            fixing commit
                                                  |
                                          cherry-pick fix
```

结果：{v1.1, v1.2, v2.0, v2.1, v2.2, v2.3, v2.4, v2.5, v2.6, v3.0}

注意：cherry-pick 的修复（v2.5, v2.6）不会被 `git tag --contains fixing_commit` 排除，因为 cherry-pick 产生的是新 commit。这是误报，第二层处理。

**性质：一定不漏。** 两种追溯方式互补，覆盖文件迁移场景。

#### 第二层：排除 cherry-pick 修复的版本

**原理**：其他分支可能通过 cherry-pick 独立应用了修复。这些版本虽然不包含原始 fixing commit，但代码已经是修复后的状态。

**操作**：对候选范围内的版本，检测是否存在与 fixing commit 相同的 patch（通过 `git patch-id` 或检查修复代码是否完整存在）。如果已修复，排除。

结果：{v1.1, v1.2, v2.0, v2.1, v2.2, v2.3, v2.4, v3.0}

**性质：一定不漏。** 只有确认修复已应用才排除。

#### 第三层：筛选变更版本

**原理**：漏洞状态只可能在代码发生变更时改变。如果两个版本之间相关代码完全一样，它们的漏洞状态一定相同。

**操作**：在候选范围内，比较相邻版本的相关代码，找出发生变更的版本。只有这些变更版本才需要进一步分析。

**性质：一定不漏。** 不做任何排除，只是筛选出需要检查的版本。

#### 三层之后的状态

经过三层处理，我们得到了：
1. 一个**可靠但偏大的候选范围**（从代码首次引入到补丁应用，排除了已修复版本）
2. 候选范围内**所有代码发生变更的版本列表**

这个范围保证不漏。范围偏大的原因是：代码首次引入 ≠ 漏洞引入。相关代码可能在 v1.1 就存在了，但漏洞是 v2.0 的一次修改才引入的。v1.1 到 v2.0 之间的版本是误报。

### 阶段二：精确定位漏洞引入点

阶段一给出了候选范围和变更点列表。阶段二的目标是在这些变更点中找到漏洞真正引入的那个点，从而精确确定受影响版本的起始位置。

#### 第一步：通过 deleted lines 缩小起点范围

**思路**：在候选范围的 states 中，找到能确定"已有漏洞"的版本。这些版本本身不是起点（起点在它们之前或等于它们），但可以排除它们之后的版本作为起点候选。

**方法**：检查 patch 中的 deleted lines（漏洞代码）是否存在于该版本中。如果存在，说明该版本已经有漏洞代码。

**对 deleted lines 误匹配的系统性分析**：

通过对 7 个项目 40 个 CVE 的实验，发现 deleted lines 匹配存在 24.7% 的误标率（标为 VULN 但 GT 说不受影响）。深入分析发现四类原因：

**类型 1：同一行代码出现在文件的不同位置**。例如 curl CVE-2024-2466 的 `return CURLE_SSL_CONNECT_ERROR;` 在 curl-7_46_0 的第 169 行（SSLv2 检查分支）被匹配到，但该 CVE 的漏洞位于 curl-8_5_0 的第 252 行（完全不同的函数末尾）。这是文件级行匹配的根本缺陷——不考虑代码位置。**解决方案：上下文定位匹配**，利用 hunk 的 context lines 先定位代码区域，再在该区域内检查 deleted lines。

**类型 2：代码完全一样但 GT 标注的起点更晚**。例如 curl CVE-2023-38546 的 `free(co->version);`，在 curl-6_5 和 curl-7_10（GT 起点）中上下文完全相同（同一函数、同一逻辑），但 GT 认为 curl-6_5 不受影响。这可能是 GT 标注精度问题——漏洞实际上在更早版本就存在。**处理方式：标记为待验证**，后续由 LLM 确认或作为 benchmark 修正的候选。

**类型 3：非 release tag 漏网**。例如 openssl 的 `LEVITTE_after_const` tag 未被 tag filter 过滤。**解决方案：补充 tag filter 规则**。

**类型 4：唯一的 meaningful deleted line 是通用代码**。例如 qemu CVE-2020-1711 只有一条 meaningful deleted line `uint64_t lba;`，这个变量声明在 iscsi 模块中到处存在。**处理方式：当 patch 只有极少量（1-2 条）meaningful deleted lines 时，标记为低置信度**，不作为确定性排除依据，交给 LLM。

**实验结果（96 CVE，8 个 repo）**：

采用上下文定位匹配（类型 1 解决方案）+ tag filter 修复（类型 3）后：

| 分类 | 比例 | 含义 |
|------|------|------|
| EXACT | 58.3% | 精确找到 GT 起点 |
| SAFE | 33.3% | 找到的点在 GT 起点之后（偏保守，不会误包含） |
| EARLY | 8.3% | 找到的点在 GT 起点之前（找过头，大部分确认为 GT 标注错误） |

**全量实验结果（411 CVE，8 个 repo）**：

| 分类 | 比例 | 含义 |
|------|------|------|
| EXACT | 56.8% (176) | 精确找到 GT 起点 |
| SAFE | 31.0% (96) | 偏保守，不会误包含 |
| EARLY | 12.3% (38) | 找过头 |
| NoVuln | 22.6% (93) | 无 meaningful deleted lines，程序分析无法定位 |

EXACT+SAFE = 87.7%，不会产生误包含。

**大距离 case 的根因分析**：

SAFE 大距离（>50 版本，找得太晚）分两类：
1. **信号不足**（md<=3）：只有 1-3 条 meaningful deleted line，在早期版本代码变了就匹配不上。例如 CVE-2023-27538（md=1, dist=131），CVE-2023-3817（md=1, dist=69）。
2. **代码大幅演化**（md>3 但距离仍大）：虽然有大量 deleted lines，但早期版本代码经历了函数重写、变量改名等重大重构，全部匹配不上。例如 CVE-2020-35965（md=12, dist=310），CVE-2020-12829（md=63, dist=71）。

EARLY 大距离（<-10 版本，找得太早）分两类：
1. **GT 标注不精确**：漏洞代码实际上比 GT 标注的更早就存在。例如 CVE-2023-38039（md=19, dist=-108），代码在 curl-7_20_0 和 GT 起点 curl-7_84_0 中完全一样。
2. **非 release tag 漏网**：如 OpenSSL 的 `OpenSSL_0_9_8-post-auto-reformat` 等内部 tag。

**结论：程序分析的极限**。大距离问题的根因是代码演化和信号不足，这是行级文本匹配的天然局限。程序分析能独立解决 176 个 CVE（42.8%），剩余 227 个需要进一步分析。

##### 全量根因分析（411 CVE，14 个深度代码分析 + 全量程序化分类）

**SAFE 96 个（找到 VULN 但晚于 GT 起点）的根因分布**：

| 根因 | 数量 | 平均距离 | 含义 | 处理方式 |
|------|------|---------|------|---------|
| del_absent | 40 | 80 | deleted lines 在 GT 版本中完全不存在，代码被重写 | 需要 LLM |
| file_not_found | 20 | 53 | 文件在 GT 版本中不存在（跨文件迁移遗漏） | 需要 LLM |
| del_partial | 17 | 67 | 部分 deleted lines 存在，部分不存在，代码部分重写 | 需要 LLM |
| del_in_file+no_context | 13 | 79 | deleted lines 在文件中存在但上下文匹配不上 | 可优化程序分析 |
| del_in_file+context_found | 6 | 38 | deleted lines 和上下文都在，但不在 region 内 | **放大 region_size 即可修复** |

**EARLY 38 个（找到 VULN 但早于 GT 起点）的根因分布**：

| 根因 | 数量 | 含义 |
|------|------|------|
| both_match_diff_code | 29 | deleted lines 在 EARLY 和 GT 版本中都匹配到，**高度疑似 GT 标注不精确** |
| unknown | 9 | 需要逐个人工核查 |

**no_context_match 28 个（有 meaningful deleted lines 但分类为 NoVuln）的根因分布**：

| 根因 | 数量 | 含义 | 处理方式 |
|------|------|------|---------|
| context_found_but_del_not_in_region | 12 | 上下文定位成功但 region 太小 | **放大 region_size 即可修复** |
| del_exists_globally_but_context_missing | 8 | deleted lines 存在但上下文完全不同 | 可优化/需要 LLM |
| file_not_found | 5 | 文件不存在 | 跨文件追踪改进 |
| del_not_found_anywhere | 3 | deleted lines 完全不存在 | 需要 LLM |

**可直接改进的**：6 + 12 = 18 个 CVE，放大 region_size 参数即可修复，不需要 LLM。

**GT 标注问题**：29 个 EARLY 案例高度疑似 GT 标注不精确（漏洞实际存在于更早版本）。这些需要逐个验证。

##### 程序分析失效的 5 种语义模式（基于 14 个 CVE 的深度代码对比）

**模式 1：缺失防御型漏洞（对应 NoVuln，93 个 CVE）**

修复只新增防御性代码，不删除任何有意义的代码行。漏洞的本质是"代码缺少某个保护"而非"代码做了某个错误操作"。

示例：FFmpeg CVE-2020-12284 的修复仅新增 `if (length > end - start) return AVERROR_INVALIDDATA;`，不删除任何代码。QEMU CVE-2020-14394 的修复引入新变量 `link_cnt` 限制链表遍历深度。

LLM 需要的能力：理解修复代码"防止了什么"，然后检查目标版本中对应的代码区域是否缺少这个保护。这是检测代码的**缺失**，传统匹配方法无法处理。

**模式 2：变量/结构体重命名（对应 SAFE 大距离的一部分）**

漏洞逻辑完全相同，但变量名在代码重构中发生了变化。

示例：FFmpeg CVE-2020-35965 中，n0.11 版本使用局部变量 `ymin`，n2.3 之后重构为结构体成员 `s->ymin`。循环 `for (y = 0; y < ymin; y++)` 和 `for (y = 0; y < s->ymin; y++)` 是同一个漏洞（用不可信值作循环上界），但文本匹配无法识别。

QEMU CVE-2020-12829 类似：`width`/`height` 在 v5.1.0 被重命名为 `operation_width`/`operation_height`。

LLM 需要的能力：识别不同命名的变量是否代表同一个逻辑值。

**模式 3：代码整体重写（对应 SAFE 大距离的一部分）**

同一个功能被完全重写，代码文本没有任何相似度，但漏洞模式相同。

示例：curl CVE-2023-27538 中，SSH 连接复用的凭证检查机制在 curl-7_83_1 才引入（作为对 CVE-2022-27782 的修复），之前根本没有这个检查——这意味着更早的版本**更加不安全**。程序分析找不到根本不存在的代码。

LLM 需要的能力：理解"完全没有安全检查"比"有一个有缺陷的安全检查"更危险。

**模式 4：控制流/架构变化（对应 EARLY 的 WRONG_CONTEXT）**

代码行表面相同，但在不同的控制流架构中语义完全不同。

示例：curl CVE-2023-38545 中，SOCKS5 代理处理在 curl-7_69_0 从同步代码重构为非阻塞状态机。旧版本的 `socks5_resolve_local = TRUE` 在同步执行中正确工作，但新版本的状态机中同一个变量在状态切换间被错误覆盖。程序分析看到变量名一样就匹配了，但漏洞只在状态机版本中存在。

LLM 需要的能力：理解代码的执行模型（同步 vs 异步/状态机），判断控制流变化是否引入了漏洞。

**模式 5：上下文演化但漏洞行不变（可程序分析改进）**

漏洞代码行本身在所有受影响版本中都存在且文本一致，但周围的上下文代码发生了变化，导致我们的 context-aware 匹配定位失败。

示例：curl CVE-2024-8096 中，`gnutls_ocsp_status_request_is_checked(session, 0) == 0` 在从 curl-7_41_0 起的所有受影响版本中都存在。但上下文行（OCSP 响应解析的详细逻辑）在 curl-7_43_0 才引入。工具因无法定位上下文而放弃匹配。

改进方向：放松上下文匹配——当漏洞行本身足够独特（如包含特定函数调用），即使上下文不完全匹配也可标记为 VULN。

##### LLM 需要处理的任务清单

| 类型 | 数量 | LLM 任务 | 输入 | 难度 |
|------|------|---------|------|------|
| NoVuln（模式 1） | 93 | 检测目标版本是否缺少修复添加的保护 | fix diff + 目标版本代码 | 中 |
| 变量重命名（模式 2） | ~20 | 识别不同命名是否为同一逻辑值 | fix diff + 两版本代码对比 | 低 |
| 代码重写（模式 3） | ~30 | 判断不同实现是否有相同漏洞模式 | fix diff + 漏洞描述 + 目标版本代码 | 高 |
| 控制流变化（模式 4） | ~15 | 判断架构变化是否影响漏洞可触发性 | fix diff + 两版本代码对比 | 高 |
| 上下文演化（模式 5） | ~30 | 可先尝试放松 context 匹配，失败再用 LLM | fix diff + 目标版本代码 | 低 |
| GT 验证 | ~10 | 确认是否为 GT 标注错误 | 两版本代码对比 | 中 |

## 总结

| 阶段 | 层 | 操作 | 结果 |
|------|-----|------|------|
| 阶段一 | 第一层 | 追溯代码首次引入，排除修复后版本 | 最大候选范围 |
| 阶段一 | 第二层 | 检测 cherry-pick 修复 | 排除跨分支已修复版本 |
| 阶段一 | 第三层 | 找代码变更点 | 需要检查的版本列表 |
| 阶段二 | — | 判断变更点是否引入漏洞 | 精确定位起点 |

阶段一保证不漏，阶段二提高精度。

## 与现有方法的对比及创新点

### 现有方法的范式

**Tracing 类**（VCCFinder, V-SZZ, Lifetime, SEM-SZZ, TC-SZZ, LLM4SZZ）：
选漏洞语句 → blame 追溯 → 选 introducing commit → 推断版本。每一步用启发式，核心目标是**精确定位引入漏洞的 commit**。

**Matching 类**（ReDeBug, VUDDY, MOVERY, V1SCAN, FIRE, VULTURE）：
从 patch 提取签名 → 在目标版本匹配。核心目标是**逐版本判断是否包含漏洞特征**。

两类方法都试图一步到位同时解决 recall 和 precision，结果两者都做不好。

### VARA 的创新点

**创新点 1：两阶段 recall-first pipeline（方法论创新）**

现有 12 个工具无一采用"先保证召回、再过滤误报"的策略。它们在每一步的设计中都在 recall 和 precision 之间做权衡（如 blame 的保守策略、匹配的严格条件），导致两者都受限。VARA 将二者解耦：阶段一只管不漏，阶段二只管去误报。这使得每个阶段可以独立优化，避免相互制约。

**创新点 2：追踪文件引入而非漏洞语句（技术创新）**

现有 tracing 工具的核心难题是"哪行代码是漏洞代码"和"哪个 commit 引入了漏洞"——这两个问题都没有确定性答案，只能靠启发式或 LLM 猜测。VARA 回避了这两个问题：不判断哪行代码是漏洞，只追踪**相关文件最早出现的时间**。文件引入时间是 git 历史中的确定性事实，不依赖任何启发式。范围可能偏大，但保证不漏，偏大的部分交给阶段二处理。

**创新点 3：跨文件迁移与跨分支覆盖的完整处理（技术创新）**

现有工具对跨文件和跨分支场景处理不足：
- 跨文件：`git log --follow` 只追踪文件重命名，无法追踪代码从一个文件迁移到另一个文件。`git blame -C` 在代码被修改后失效。`git log -S` 能追踪但性能不可接受（10-25 秒/次）。
- 跨分支：大多数工具只分析主分支，V-SZZ 虽支持跨分支但匹配策略简陋。

VARA 的解决方案：
- 跨文件：在文件引入 commit 的 parent 上做一次定向 `git grep`（<0.1 秒），检测代码是否在其他文件中已存在，如果是则递归追溯旧文件。
- 跨分支：`git log --all` 搜索所有分支上的文件引入 commit，`git tag --contains` 天然覆盖分支合并。多个 fixing commit 的情况取交集排除（只有全部修复都应用才算已修复）。

---

## Phase 2 重新设计（2026-04 备忘）

### 起因

之前 Phase 2 step 2 的草稿是「把没匹配上的 case 丢给一个综合 prompt」。基于真实数据深入分析后发现两个问题：(1) 失败 case 有不同性质，应该走不同 pipeline；(2) 把所有事都交给单次 prompt 仍然是黑盒，论文上立不住。

### 数据驱动的失败桶

411 CVE 的真实分布（96 SAFE + 38 EARLY + 93 NoVuln）：

| 桶 | 数量 | 性质 | 平均 dist |
|---|---|---|---|
| DEL_PARTIAL | 30 | 程序 corner case，脏代码字面还在文件里，只是 context 顺序变了定位失败 | 67-79 |
| DEL_ABSENT | 40 | 函数完全被改写（变量改名/结构重构），需要语义理解 | 80 |
| FILE_MOVED | 20 | patch 的文件路径在目标版本不存在，是追溯/工程问题 | 53 |
| ADD_ONLY (NoVuln) | 93 | 没有 deleted lines，deleted-line fingerprint 完全失效 | — |

### 重新分阶段：工程问题 vs 语义问题

**阶段 A — 工程性追溯问题（确定性，不用 LLM）**

FILE_MOVED 不该交给 LLM。它的本质是：候选范围算对了（Layer 1 的跨文件追溯能把这些 tag 纳入候选），但 vuln_classifier 去看代码时不知道文件叫啥。Layer 1 的跨文件追溯只用来产出"哪些 tag 进候选"，没有产出"patch 的文件在 tag X 上对应哪个路径"的映射。

**修法：加 Phase 1.5 — 路径解析层**
- 给每个 patch file 建一张 `path_map: tag → actual_path_at_tag`
- 路径在目标 tag 不存在时，用 `git ls-tree | grep <basename>` + `git grep <函数名/特征 token>` 找到真位置
- vuln_classifier 用 path_map 而不是 `fp.path` 直接取文件
- 这是确定性程序逻辑

**阶段 B — 漏洞片段识别（LLM 的领域）**

剩下三类（DEL_PARTIAL/DEL_ABSENT/ADD_ONLY）的共同本质：deleted-line fingerprint 不够用，要换一种方式表达"漏洞是什么"。区别只是换成什么：

| 桶 | 用什么当 fingerprint |
|---|---|
| DEL_PARTIAL | 仍是 deleted lines，但允许 fuzzy 匹配 + 更宽松的定位 |
| DEL_ABSENT | 从整个 diff 抽出 root cause 的语义描述 |
| ADD_ONLY | 用 added lines + context 当**反向** fingerprint（找它的"缺席"）|

LLM 拿到 fingerprint 之后做的事是统一的：「这个语义在目标代码里成立吗？」

### LLM 的两个角色

**角色 1：离线漏洞画像（per CVE，一次，可缓存）**

- **输入**：fix diff（+ 可能的 CVE 描述）
- **输出**：结构化的 `VulnerabilityProfile`：
  ```
  {
    cve_id: ...
    fragment_type: DELETED | ROOT_CAUSE | ANTI
    root_cause: "loop bounded by untrusted ymin without capping at buffer height"
    key_function: "decode_frame"
    key_tokens: ["ymin", "s->ymin", "AV_RB16"]
    bad_pattern: "for (... < ymin ...) without prior min(ymin, h)"
    good_pattern: null            # ANTI 时填: "if (length > end - start) return ERR;"
    search_hints: [...]
    alt_paths: [...]
  }
  ```
- **属性**：411 CVE × 1 次 ≈ 411 次离线调用，可缓存到 `data/profiles/<cve>.json`，重跑零成本

**角色 2：在线 Agent 验证（per unique state，按需）**

- **输入**：profile + 候选 tag + 工具集（git grep / read_file / list_dir）
- **任务**：用 profile 去这个 version 里 instantiate
  1. 按 `key_function` 找函数体
  2. 找不到 → 按 `key_tokens` grep
  3. 还找不到 → 按 `alt_paths` 找文件
  4. 找到 → 看 `bad_pattern` 是否存在 / `good_pattern` 是否缺失
  5. 输出 verdict + 引用代码片段
- **属性**：只对 unique state 触发（用现有 Layer 3 dedup），agent 任务边界很窄（profile 已经规定好"找什么"）

### 完整 pipeline

| 阶段 | 类型 | 干啥 | 状态 |
|---|---|---|---|
| Phase 1 (3 layers) | 程序 | 候选范围 | 已完成 |
| Phase 1.5 | 程序 | 路径解析层 | **待加** |
| Phase 2-1 | 程序 | context-aware deleted-line 匹配 | 已完成 |
| Phase 2-2a | LLM 离线 | 漏洞画像（per CVE） | **待加** |
| Phase 2-2b | LLM Agent 在线 | 按需验证（per unique state） | **待加** |

### 论文方法论叙述

**为什么现有工具失败**——分两层根因：
1. **工程层**：跨分支、跨文件、cherry-pick、partial fix、tag filter 这一堆细节都做错了 → Phase 1 + Phase 1.5 解决
2. **语义层**：deleted-line fingerprint 在四种场景下失效 → Phase 2-2 解决

**LLM 的定位**：
- 离线做"语义浓缩"（fix → 结构化画像）
- 在线做"语义到代码的映射"（profile → version 中的 instantiation）
- 不做开放推理，**任务边界都很窄**

这把"我们调了 GPT 分析漏洞"升级为"我们设计了 offline-online vulnerability profiling 框架，LLM 是其中两个有界子任务的实现"。

### TODO：二级 taxonomy（关键，避免黑盒）

当前设计仍停留在「四个桶 + LLM 处理」的粗粒度。为了让方法可解释、论文站得住，下一步需要：

**对每个桶细分到具体漏洞模式（subtype）**，每个 subtype 给出：
1. **分类规则**：从 fix diff 的什么特征能确定性地判断属于这个 subtype
2. **画像 recipe**：profile 该抽什么字段、什么 pattern
3. **agent recipe**：在线验证该按什么步骤、用什么工具
4. **真实案例**：从 8 个 repo 的数据集里挑 1-2 个

ADD_ONLY 应至少分：
- ADD_ONLY/missing-bounds-check（CVE-2020-12284 类，加边界检查防越界）
- ADD_ONLY/missing-null-check
- ADD_ONLY/missing-state-reset（CVE-2022-1473 类，flush 忘 reset 计数器）
- ADD_ONLY/missing-loop-bound（CVE-2020-14394 类，加 link_cnt 防无限循环）
- ADD_ONLY/missing-init
- ADD_ONLY/missing-free / missing-cleanup

DEL_ABSENT 应至少分：
- DEL_ABSENT/variable-rename（CVE-2020-35965 类，ymin → s->ymin）
- DEL_ABSENT/struct-refactor（CVE-2020-12829 类，width → operation_width）
- DEL_ABSENT/control-flow-rewrite（CVE-2023-38545 类，同步代码 → 状态机）
- DEL_ABSENT/inline-to-helper（函数被拆/合）
- DEL_ABSENT/feature-not-yet-existed（CVE-2023-27538 类，更早版本根本没这个 check，反而更脆弱）

DEL_PARTIAL 应至少分：
- DEL_PARTIAL/order-shift（fix 的 hunk 顺序与目标版本不一致）
- DEL_PARTIAL/context-evolution（漏洞行不变但周围 context 演化）
- DEL_PARTIAL/whitespace-or-format

FILE_MOVED 应至少分：
- FILE_MOVED/rename-only（git rename，basename 不变）
- FILE_MOVED/split-or-merge（一个文件拆成多个 / 合并成一个）
- FILE_MOVED/path-restructure（目录重组，basename 可能变）

**这一层 taxonomy 的工作量在分析，不在 coding**。需要 systematic 地从数据里挖：每个桶随机抽 10-15 个 case，逐一读 fix diff + 目标版本代码，归纳 subtype。这是写论文必须做扎实的部分。

