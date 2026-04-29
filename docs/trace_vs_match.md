# Trace vs Match：两类方法的局限性分析

本文档是论文 motivation 章节的核心论证：**为什么我们选 trace 范式，而不是 match 范式**。
两类方法都有局限——这里把局限说清楚，把我们方法的 niche 说清楚。

---

## 1. 核心 claim

| | Match 范式 | Trace 范式 |
|---|---|---|
| 工作方式 | 从 fix patch 提取漏洞 signature，在每个目标版本搜索匹配 | 从 fix commit 出发，沿 git 历史回溯漏洞代码的来源 |
| Recall 上界 | **理论受限** | **理论可 100%** |
| Recall 上界的瓶颈 | signature 的表达力（无法预知代码变形） | provenance detection 的能力（探测代码来源的精度） |
| 我们的选择 | 不选 | **选** |

**核心论点**：
> Match 范式的 recall 上界是**信息论意义上的限制**——不管 signature 设计多巧，
> 漏洞代码可能以无法预知的方式变形，signature 必然漏。
> Trace 范式的 recall 上界是**工程问题**——只要 git 历史完整，
> 每个 affected version 原则上都能被识别到。

---

## 2. Match 范式的局限

### 2.1 它怎么工作

从 fix patch 中提取一个"漏洞特征"：
- ReDeBug：token n-gram
- VUDDY：function-level hash
- MOVERY：modified statement signature
- V1SCAN / FIRE：approximate matching with similarity

然后在每个目标版本中搜索这个 signature。匹配上 → 该版本受影响。

### 2.2 它一定漏的几类场景

| 失败模式 | 原因 |
|---|---|
| **A1 ADD-only fix** | patch 只新增防御代码，没 deleted lines 可提 signature |
| **A2 代码重构 / 改名** | signature 在老版本以**不同写法**存在；hash/token 匹配失效 |
| **A3 跨文件迁移** | signature 在老版本**别的文件**里；按 file 匹配会漏 |

这些不是工程问题，是**范式假设的限制**：
> Match 假设漏洞的"可检测特征"是新代码空间里的某种文本/结构 pattern。
> 但漏洞所在的**老代码空间可能根本不长这样**——signature 设计再巧也覆盖不了。

举具体例子（来自 ASE 2025 study + 我们 411 CVE 实测）：
- ReDeBug 在 1128 CVE 上 F1 = 0.725
- VUDDY F1 = 0.493（hash 严格，重构全漏）
- MOVERY F1 = 0.728
- **最佳 match 工具 F1 ≤ 0.778**（VCCFinder，但 VCCFinder 严格说是 hybrid，纯 match 都 < 0.73）

→ 工程优化（更宽松 hash、approximate match）能把 F1 从 0.5 推到 0.7，但**推不到 0.95+**。这是范式上界。

### 2.3 信息论的论证

漏洞发生在 V1 版本，patch 是在 V_fix 写的。
对每对 (V1, V_fix)，从 V_fix 的 patch 提取的 signature 是基于 V_fix 的代码空间表征。
若 V_fix 和 V1 之间发生了：
- 变量改名 → token 变了
- 函数边界调整 → hash 变了
- 文件拆分 → 路径变了
- 语义等价改写 → 任何 textual signature 都变了

signature 在 V1 上是否存在的判断，**无法仅靠 V_fix 的信息得出**。
→ Match 范式天然受限于"V_fix → V1 的代码演化幅度"，存在上界。

---

## 3. Trace 范式的优势 + Caveat

### 3.1 它怎么工作

不靠"漏洞代码长什么样"，靠 **git 历史的拓扑结构**：
- 找到漏洞代码的 introduction commit（什么时候被加进 repo）
- 找到 fix commit（什么时候被修复）
- 中间所有的 tag = affected versions

### 3.2 为什么"理论上可 100%"

git 历史是**无损记录**：每个 commit 都有 parent 关系，每个 tag 都有 commit 拓扑。
原则上：

> 一个 tag T affected ⟺ T 含有 vuln 代码的 introduction，且不含 fix。

如果 introduction 和 fix commit 都能被找到，且 tag 拓扑完整——recall 必然 100%。

### 3.3 Caveat 1：100% 是**条件 100%**

我们 Layer 1 用的 implicit 定义是：
> tag affected ⟺ tag 含有 patched file（或 ancestor file）的 introduction，且不含全部 fix commits

这个定义 trace 能 100%，但**不等于** GT 用的语义定义。

**反例（CVE-2022-1114, ImageMagick）**：
- 文件 `coders/dcm.c` 在 v6 时期就存在
- 但 vulnerable 写法（`DCMInfo->scale` 那段）是**后来某个 commit 加的**
- GT 标 7.0.10-30 affected，但 7.0.10-30 上根本没那段 vuln code
- Trace 按 `file_intro` 把 v6 早期都召回 → over-cover（实际是 GT 的语义不一致问题，但 trace 也没办法精确卡）

→ 论文里要把"affected"的定义说清楚。我们的 trace claim 是：
> **"file-exists-without-fix" 意义下的 100% recall**

GT 的语义如果偏离这个定义，差的部分要说清楚——这是**写论文的诚实**，不写会被 reviewer 打。

### 3.4 Caveat 2：path 阻碍分三类，难度不同

**A 类 — git tooling 的工程限制**（可解）：
- `--diff-filter=A` 在 git 把 split/copy 记为 Modify 时找不到 intro
- `--follow` 的 rename detection 有相似度阈值
- 跨 repo（fork chain）trace 完全断
- 改进方向：加 fallback 逻辑、用 git 的 similarity score 而不是 fixed-string

**B 类 — 代码同时被改写**（半可解）：
- 跨文件迁移时代码被重新写了一遍（不是 verbatim copy）
- 我们用 `git grep --fixed-strings` 在 parent commit 里找原文件——grep 找不到就断
- 改进方向：见第 4 节（这是我们方法的核心 niche）

**C 类 — 漏洞不在 git 历史可达范围**（基本不可解）：
- 漏洞由配置/编译选项变化触发，代码层 trace 不到
- 漏洞由依赖库的某次更新引起
- 改进方向：scope out（论文里明确不处理）

---

## 4. 关键 self-criticism：trace 在 A3 detection 用了 match 作为工具

这是个 honest 的 self-criticism——**我们的 trace 不是纯 trace**。

具体看 `app/phase1/tracing.py::trace_code_origin`：

```python
git grep --fixed-strings <deleted_line> <parent_commit>
```

这就是文本匹配。如果原文件里的代码被改写过，`--fixed-strings` 找不到 → 跨文件迁移就 detect 失败 → trace path 断。

→ 我们的 trace 在 A3 这一步**继承了 match 的全部限制**。

### 4.1 但 match-as-tool ≠ match-as-answer

差别不在"用不用文本匹配"，而在"**文本匹配的角色**"：

| | Match 流派 | Trace 流派（我们） |
|---|---|---|
| 文本匹配的角色 | **答案**："这段代码是不是 vulnerable？" | **工具**："这段代码源自哪儿？" |
| 失败时 | 直接说 "not vulnerable"（漏报） | 转向其他 trace 信号（git follow / blame / 时间戳） |
| Recall 上界 | 受 signature 表达力限制 | 受 **provenance detection** 能力限制 |

我们的 trace 在 A3 用 fixed-string grep 做 provenance detection——这是**实现选择**，不是 trace 范式的本质。
可以替换成：
- `git log --follow` 的相似度算法（默认 50% 阈值，比 fixed-string 宽松）
- AST diff
- Embedding 相似度
- **LLM-as-provenance-detector**（"这段代码是不是从那个文件搬过来的？"）

每替换一种，A3 的 detection 上限就被推高一档。

---

## 5. 我们的 niche：semantic provenance detection

把第 3、4 节合在一起，得出我们方法的精确定位：

> **Trace 范式的 recall 上界 = provenance detection 的上界。**
> 现有 trace 工具（V-SZZ / Lifetime / SEM-SZZ / LLM4SZZ）卡在
> "fixed-string grep / git blame" 这个 textual provenance 探测层。
> 我们用 **LLM 做 semantic provenance detector**，
> 把 A3 detection 从 textual 推到 semantic——
> trace 范式的 recall 上界第一次被推到接近 100%。

### 5.1 这个 contribution 跟现有 LLM-based 工作不重叠

| 工作 | LLM 用在哪 |
|---|---|
| LLM4SZZ | 用 LLM 做 commit-level vulnerability verification |
| AgentSZZ / SZZ-Agent | 用 LLM agent 做 BIC（bug-inducing commit）选择 |
| **我们** | 用 LLM 做 **provenance detection**（A3 跨文件迁移的语义判断） |

LLM 在我们方法里**职责明确、范围窄、不全能兜底**——这是论文好辩护的地方。

### 5.2 责任划分

| 阶段 | 负责什么 | 失败模式 |
|---|---|---|
| Layer 1（git topology + LLM provenance） | Recall（100% 上界） | A1 / A2 / A4 / A5 / A6 / A7 全覆盖；A3 用 LLM 推高上界 |
| LLM 排 FP（stage 2） | Precision（消除 over-cover） | 见 stage 2 设计文档 |

> 以前的工具试图用一个范式（match 或 trace 之一）同时做 R 和 P，结果两边都做不好（study 12 工具 F1 < 0.78）。
> 我们的 framework 把 R 和 P 拆开：trace + semantic provenance 拿 R，LLM filter 拿 P。
> **责任清晰，每一层有明确的上限论证**。

---

## 6. 总结：为什么我们选 trace

1. **Match 的 R 上界是范式级的**（信息论限制），工程优化推不到 95%+；
2. **Trace 的 R 上界是工程级的**（provenance detection 能力），原则上可达 100%；
3. **Trace 的瓶颈是 A3 跨文件迁移 + 代码改写**——这一步现有工具用 textual match，是 trace 自己的"内部 match"瓶颈；
4. **我们用 LLM 做 semantic provenance detector**，正面解决这个瓶颈；
5. **R 和 P 责任分开**：Layer 1 (trace + LLM provenance) 拿 R，LLM filter (stage 2) 拿 P。

→ 论文 method 章节按这个 framing 展开，每条都有明确的局限性论证 + 我们的解法。
不写 hand-wavy 的 "we use LLM"，写 "we use LLM at this specific step for this specific reason"。

---

## 7. 还要回答的问题（写论文之前）

1. **A3 + 代码改写** 的 LLM provenance detector 怎么具体设计？输入是什么、输出是什么、prompt 怎么写？
2. **"file-exists-without-fix" 定义和 GT 语义的差距** 在数据上有多大？我们要不要在 paper 里报这个 gap？
3. **C 类（不在 git 历史里的漏洞）** 在 1128 CVE 里占多少？scope out 之前要 quantify。

回答完这 3 个，trace vs match 的论证就完整了。
