# 困难与挑战

本文档梳理 vulnerability-affected version identification 任务在实际操作中遇到的困难，分 5 类。
目的是在动手设计方法之前先把"我们到底要解决什么"列清楚。

---

## A. 任务本身的困难（论文真正要解决的核心）

### A1. ADD-only fix（22.6% 的 CVE）
fix 没删任何代码，只新增防御性逻辑（NULL 检查、bounds check、计数器限制等）。漏洞的本质是"代码缺少某个保护"而非"代码做了某个错误操作"，没法用传统 deleted-line matching。

**典型例子**：CVE-2020-12284 (FFmpeg) — fix 只加 `if (length > end - start) return AVERROR_INVALIDDATA;`。

### A2. 代码重构 / 函数改名
漏洞代码还在，但变量名、结构体、函数边界变了。文本匹配/AST 哈希都失效。

**典型例子**：CVE-2020-35965 (FFmpeg) — fix 删的 `for (y = 0; y < s->ymin; y++)` 在 n0.11 写法是 `for (y = 0; y < ymin; y++)`（局部变量 vs struct 成员，相同语义）。

### A3. 跨文件迁移
漏洞代码从一个文件搬到另一个文件，原文件路径在老版本不存在。`git log --follow` 只追踪 `git mv`，搬+改后失效。

**典型例子**：qemu 的 `usb-redir.c` → `hw/usb/redirect.c`；FFmpeg 的 `applehttp.c` → `hls.c`。

### A4. 跨分支独立引入
同一文件在不同分支被独立 add（不同的 add commit）。`git log --follow` 只追当前分支历史，另一分支的版本全部漏报。

**典型例子**：httpd `mod_proxy_uwsgi.c` 在 trunk 和 2.4.x 分别有独立 add commit。

### A5. Cherry-pick 修复
fix 在主分支后，其他分支通过 cherry-pick 独立应用了修复。这些版本不含原始 fix commit（hash 不同），但代码已修复。`git tag --contains fix_commit` 排除不到，被误标为受影响。

### A6. 部分修复
一个 CVE 有多个 fix commit，每个修一方面。某版本只有部分 commit → 漏洞仍在但 `git tag --contains` 任一 commit 就排除会漏报。正确做法是只排除包含**全部** fix commit 的版本。

### A7. 漏洞从文件创建时就存在
没有"引入 commit"可追溯——文件第一次 commit 就带漏洞。SZZ 系工具默认假设"deleted line 之前必有引入 commit"在此失效。V-SZZ 部分解决（用 line mapping）但仍依赖 deleted lines。

---

## B. Ground truth 的困难（评估和数据本身的问题）

### B1. NVD 标注大量错误
公开漏洞数据库不可靠：
- He et al. [TDSC'24] 在 Linux Kernel 上发现 NVD 有 5.7% FP + 21.34% FN
- 我们在自己的实验中也已发现 1000+ 个错误版本

### B2. GT 偏窄（systematic bias）
GT 倾向只标"还在维护的分支"。例如某 CVE 在 wireshark 1.10.0 和 1.99.0 上代码完全相同，但 GT 只标 1.99.0+ 受影响——因为 1.10.0 已 EOL，没人 backport fix。**老分支即使有同样 bug 也不被标**。

### B3. GT 偏宽
NVD 经常用"all versions before X"这种保守描述，但老版本可能根本没那个 feature。

### B4. 人工标注成本高
Study 自己标 1128 CVE 用了 0.5 人时/CVE，总共约 564 人时——大部分研究组负担不起。这导致已有 benchmark 大多很小（V-SZZ 只 172 CVE）。

---

## C. 方法论 / 评估的困难

### C1. 没有 paradigm-level 的统一框架
现有 12 个工具（Study 评估）每个都用自己的 ad-hoc 组合：matching 系用 hash/AST/IPDG/taint，tracing 系用 SZZ 各种变体，没人系统化为统一框架。结果是每篇 paper 都在叙述自己的 specific innovation，整个领域缺乏"方向感"。

### C2. 现有评估指标不区分 case 类型
一个总体 F1 数字掩盖了"哪类失败模式解决了、哪类没解决"。Study 已部分修正（按 patch type 报数），但没人按 A1-A7 这种细粒度分桶报数。

### C3. Reproducibility 差
很多工具只在自己的小 dataset 上跑（如 V-SZZ 的 172 CVE / VERCATION 的 74 CVE），自报 F1 都是 90%+，但 Study 在 1128 CVE 大 benchmark 上重测后全部跌到 < 45%。

---

## D. 工程的困难

### D1. 大规模成本
1128 CVE × 平均几百 candidate version × LLM 调用 = 几千美元 / 几小时。

### D2. Git 操作慢
`git tag --contains <commit>` 在大仓库（OpenSSL 1300+ tags）单次几秒；`git log --all` 全量扫描更慢；跨 1128 CVE 全量跑动辄几小时。

### D3. 缓存复杂
跨 CVE / 跨 project / 跨 git 操作的缓存怎么设计才不冲突 + 不浪费空间，是个细节但不简单。

---

## E. LLM 相关的困难

### E1. LLM hallucination
LLM 会编造代码里不存在的 check。我们实测 CVE-2020-9430，LLM 声称 v1.10.0 的 wimax_decode_dlmapc() 已含 `if (mac_len <= sizeof(mac_crc))` 检查——实际代码里根本没有。

### E2. LLM 对长代码 context 注意力衰减
扔整个文件进去效果反而差；需要精确提取相关函数体。

### E3. LLM 调用成本和延迟
Agent 每个 case 几次到几十次调用，成本+延迟都不可忽略。

### E4. 评估时的 data leakage
LLM 可能见过 fix commit（公开数据集 + 互联网爬取）。SZZ-Agent 专门构造了 LLM 训练 cutoff 之后的数据集 (DS_LINUX-26) 来排除 leakage——这是 baseline 做得好的地方，我们也得做。

---

## 总结：这些困难对论文意味着什么

| 类别 | 是否论文核心 | 角色 |
|---|---|---|
| **A 任务本身的困难** | ✅ **核心** | 我们方法要正面解决的问题；motivation 来源 |
| **B GT 困难** | 🟡 副产品 | 工程贡献：修正 GT 错误。可以作为单独 contribution，但不是 main story |
| **C 方法论困难** | ✅ **核心** | 我们 framework 的 framing 来源（无统一框架 → 我们提供） |
| **D 工程困难** | ⚪ 实现细节 | 影响实验设计，但不是 paper 卖点 |
| **E LLM 困难** | 🟡 必须处理 | 不解决就没法写 LLM-based 方法；但解决方式不是核心创新 |

**论文 narrative 应该围绕 A + C 展开**：
- A 是"为什么现有工具集体失败"的具体证据
- C 是"我们提出的解法跟现有不同"的方法论叙事

B/D/E 是支撑性贡献和工程细节，写在 evaluation 和 limitation 章节。

---

## 接下来要回答的问题

设计方案前，先问自己：

1. **A1-A7 这 7 个任务困难，哪几个是"general agent + skill 库"能解决得比专用工具更好的？**
2. **C1 这个"无统一框架"的痛点，我们要不要正面提出统一框架？还是只是 implicit 用？**
3. **B 类 GT 困难，我们要主动修正 GT 并报告，还是只在原始 GT 上比 F1？**

回答完这 3 个，方法论方向就清晰了。
