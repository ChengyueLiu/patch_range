# Related Works — 相关工作整理

本文档整理 vulnerability-affected version identification 任务相关的 19 篇核心工作（外加 Study 本身），按时间发展和方法论分类，给出每篇的核心思路、方法、结果、对我们的启示。

---

## 一、整体概述（写论文用的草稿段落）

围绕这个任务，学术界主要发展出**两条技术路线**。**Matching 路线**始于 ReDeBug [S&P'12] 的 token n-gram 匹配，经 VUDDY [S&P'17] 函数级哈希、MVP [USENIX'20] 同时利用补丁前后签名、MOVERY [USENIX'22] / V1SCAN [USENIX'23] 处理被修改过的克隆，到 FIRE [USENIX'24] 的 taint 分析、Vision [ASE'24] 的程序依赖图——一脉相承，从 fixing patch 提取漏洞特征、在每个目标版本中搜索匹配。**Tracing 路线**始于 SZZ 算法 [MSR'05]，VCCFinder [CCS'15] 首次面向漏洞场景，V-SZZ [ICSE'22] 提出基于 SZZ 的版本范围推断，SEM-SZZ [TSE'24] 用程序切片专门处理 add-only 修复，VERCATION [arXiv'24] 和 LLM4SZZ [ISSTA'25] 引入大模型辅助 commit 选择，最近 AgentSZZ [arXiv'26] 与 SZZ-Agent [arXiv'26] 进一步将其升级为 LLM agent 框架。两条路线各有侧重：matching 擅长精确验证代码片段的存在性，tracing 不依赖代码字面匹配、对代码演化更鲁棒。此外，He et al. [TDSC'24] 探索了将代码 patch 与 developer logs 等多信号融合的混合路线，AFV [ASE'22] 提出"vulnerability-centric"思路（限于 PHP）。然而，ASE 2025 上一项系统性 study [arXiv:2509.03876] 基于 1128 个 CVE、9 个 C/C++ 项目对 12 个代表性工具的评估，揭示了这条研究线的整体瓶颈：**没有任何单一工具的 accuracy 超过 45%，最佳 F1 也不超过 78%；即使简单 ensemble 多个工具，accuracy 仍低于 60%。**

---

## 二、时间线（按年份）

```
2005:                                   SZZ 原文 (MSR)
2012:  ReDeBug (S&P)
2015:                                   VCCFinder (CCS)
2017:  VUDDY (S&P)
2020:  MVP (USENIX)
2022:  MOVERY (USENIX)                  V-SZZ (ICSE)
       AFV (ASE) [PHP-only]            Lifetime (USENIX)
2023:  V1SCAN (USENIX)
2024:  Vision (ASE)                     SEM-SZZ (TSE)
       FIRE (USENIX)                    VERCATION (arXiv)
       Vul4Java (ASENS) [Java-only]     He et al. (TDSC) [混合]
2025:                                   LLM4SZZ (ISSTA)
                            ↓
2025-09: Study (arXiv) ──── 揭示 < 45% accuracy 瓶颈
                            ↓
2026:                                   AgentSZZ (arXiv)
                                        SZZ-Agent (arXiv)
─────────────────────────  ─────────────────────────
       Matching 路线                    Tracing 路线
```

---

## 三、按方法 paradigm 分类 + 关键差异表

⚠️ 备注列标记了**写论文时需要警惕的点**：与我们工作可能重叠或必须明确区分的工作。

| 工具 | 年份 | venue | 路线 | 核心代表性思路 | 用了哪些 feature 维度 | ⚠️ 备注 |
|---|---|---|---|---|---|---|
| SZZ 原文 | 2005 | MSR | Tracing 奠基 | git annotate 回溯 deleted lines | 存在（deleted lines） | — |
| ReDeBug | 2012 | S&P | Matching 奠基 | token n-gram + hash 匹配 | 存在 | — |
| VCCFinder | 2015 | CCS | Tracing | SVM 分类 commit metadata | 存在（commit 特征）| — |
| VUDDY | 2017 | S&P | Matching | 函数级 hash + abstraction | 存在（function hash） | — |
| MVP | 2020 | USENIX | Matching | 程序切片抽 vuln+patch signature | 存在 + 缺失 | — |
| MOVERY | 2022 | USENIX | Matching | "最早的"vuln function + core lines | 存在 + 缺失 | — |
| V-SZZ | 2022 | ICSE | Tracing | 追溯**最早**改 vuln line 的 commit | 存在（位置感知） | — |
| Lifetime | 2022 | USENIX | Tracing 实证 | 估计 vuln 在代码中存活时间 | 存在 + 启发式 | — |
| **AFV** | **2022** | **ASE** | **"Vulnerability-centric"** | **抽 vulnerability logic（PHP）** | **语义（最接近我们）** | ⚠️ **已讲过"patch assumption 是问题"——novelty 必须明确区分**：他们针对 PHP web，方法是 PHP-specific 静态分析；我们是通用 C/C++ 框架，把 4 维度系统化 |
| V1SCAN | 2023 | USENIX | Matching | 代码分类 + version-based hybrid | 存在 + 上下文 | — |
| Vision | 2024 | ASE | Matching | 加权 IPDG + 处理 add-only | 存在 + 缺失 + 部分语义 | — |
| SEM-SZZ | 2024 | TSE | Tracing | 程序切片 + 数据/控制流，针对 add-only | 缺失 + 语义 | — |
| VERCATION | 2024 | arXiv | Tracing+LLM | LLM (Few-shot+CoT) refine 特征 + AST clone | 存在 + 语义 | — |
| **FIRE** | **2024** | **USENIX** | **Matching** | **Multi-stage filtering + taint differential** | **存在 + 缺失 + 语义** | ⚠️ **它的 "multi-stage" ≠ 我们的 "multi-form"**——它是同一种特征的多阶段过滤，我们是不同种特征的多形式融合。论文必须明确区分，否则审稿人会问"FIRE 不也是多阶段吗" |
| **He et al.** | **2024** | **TDSC** | **混合** | **Patches + developer logs + version tree** | **多信号融合（最像我们）** | ⚠️⚠️ **跟我们任务最像**。必须讲清"我们是 framework，他们是 ad-hoc 工程"——他们已在工程层面集成多信号但作为 engineering tricks；我们是 principled 4 维度框架，He et al. 是我们框架的不完整 instance |
| **Vul4Java** | **2024** | **ASENS** | **Matching (Java)** | **Two-stage + SACG** | **函数 + 调用图** | ⚠️ **下错的 PDF**：study 里的 Verjava (Sun et al, ICSME 2022) 不是这一篇。两者标题相似（都是 "Java 两阶段"）。后面有空补回真正的 Verjava |
| LLM4SZZ | 2025 | ISSTA | Tracing+LLM | Context-enhanced + rank-based LLM 选 BIC | 存在 + LLM 评估 | — |
| **Study** | **2025** | **arXiv** | **基准** | **1128 CVE benchmark + 12 baseline 评估** | **—** | 我们的 motivation 来源；benchmark 锚点 |
| **AgentSZZ** | **2026** | **arXiv** | **Tracing+LLM Agent** | **ReAct loop + 5 git tools + domain knowledge** | **存在 + agent 探索** | ⚠️⚠️ **抢了 "LLM agent 做 vuln tracing" 这个角度**。但他们输出 BIC commit 不是 V_aff 版本集合；我们直接做 V_aff，省去 commit→version 映射步骤。差异化点必须在 framework 层面而非"也用 agent" |
| **SZZ-Agent** | **2026** | **arXiv** | **Tracing+LLM Agent** | **2 阶段（SZZ + binary search 全 file 历史）** | **存在 + 缺失 + agent 探索** | ⚠️⚠️ Stage 2 binary search **正好解决我们说的 ADD-only 问题**——multi-form 在 ADD-only 维度被部分预占。同 AgentSZZ：他们输出 BIC commit 不是 V_aff |

---

## 四、每篇论文详细分析

按"奠基 → Tracing 系演进 → Matching 系演进 → 混合/特殊 → Study → Agent"顺序。

---

### 4.1 SZZ 原文（MSR 2005）

> Śliwerski, Zimmermann, Zeller. **When Do Changes Induce Fixes?**

**核心思路**：从 bug 报告出发追溯引入它的 commit。

**方法**：
1. 把 bug 报告（BUGZILLA）通过语法+语义置信度关联到 fix commit（CVS）
2. 对 fix 修改的行，用 `cvs annotate` 找最后一次改这些行的更早 commit
3. 那个 commit = "fix-inducing change"
4. 用 "suspect" 概念过滤：hard suspect（在 bug 报告之后才提交，排除）/ weak / partial fix / 真正的 inducing

**对我们的意义**：所有 SZZ 系列工具的起点。背景章节必引。

---

### 4.2 VCCFinder（CCS 2015）

> Perl et al. **VCCFinder: Finding Potential Vulnerabilities in Open-Source Projects to Assist Code Audits.**

**核心思路**：训练 SVM 分类器，预测哪些 commit 是 vulnerability-contributing commits (VCCs)。

**方法**：
- 特征：code metrics + git metadata（作者、提交时间等）
- 数据：66 GitHub 项目 / 170k commits / 640 VCCs
- 服务于代码审计场景

**对我们的意义**：原本不直接做 affected version——study 改造它来：找 VCC → tag-contains 推版本。是 vulnerability-aware SZZ 的早期代表，但本质是个 commit 分类器。

---

### 4.3 V-SZZ（ICSE 2022）

> Bao, Xia, Hassan, Yang. **V-SZZ: Automatic Identification of Version Ranges Affected by CVE Vulnerabilities.**

**核心思路**（V-SZZ 最重要的 insight）：bugs 是被"最近的 commit"引入的，但 **vulnerabilities 是 foundational**——在最早的版本就引入。SZZ 算法对 bug 设计，对 vuln 不适用。

**方法**：
- 用 **line mapping** 算法找**最早**修改 vulnerable lines 的 commit（不是 last-modifying）
- 然后用 tag-contains 推 version range

**结果**：
- 172 CVE benchmark（5 C/C++ + 41 Java 项目）
- vulnerable version F1 = **0.928 (C/C++) / 0.952 (Java)**——但是在他们自己 GT 上
- Study 在 1128 CVE 大 benchmark 重测后大幅下降到 < 45%

**限制**：仍依赖 deleted lines；ADD-only fix 处理不了。

**对我们的意义**：最直接的 baseline；他们的高 F1 暴露了 GT 偏差问题（GT 错误的存在）；他们的 dataset 就是 V-SZZ paper 的标注集。

---

### 4.4 Lifetime（USENIX Sec 2022）

> Alexopoulos et al. **How Long Do Vulnerabilities Live in the Code? A Large-Scale Empirical Measurement Study on FOSS Vulnerability Lifetimes.**

**核心思路**：实证研究 vulnerability 在代码中存活时间（Chromium 平均 2 年，OpenSSL 7 年，整体 4 年）。

**方法**：启发式算法估计漏洞引入时刻（≈ identifying inducing commit）。

**对我们的意义**：本质是 measurement paper，不是真正的工具——study 把它的引入估计当作 tracing baseline 用。它的"启发式估计"接近 SZZ 变体。

---

### 4.5 SEM-SZZ（TSE 2024）

> Tang, Ni, Huang, Bao. **Enhancing Bug-Inducing Commit Identification: A Fine-Grained Semantic Analysis Approach.**

（同 V-SZZ 一组的浙大 Lingfeng Bao）

**核心思路**：直接攻击 add-only fix 问题（Linux 17.46% bug-fix 是 add-only）。

**关键启发**：bug-inducing commit 通常能通过追溯 added lines **附近**的两条 unmodified lines 找到（85% 命中率），不用追溯整个 block 那样太粗。

**方法**：
1. Program slicing 抽 vuln-relevant 程序段
2. 对比"前一版本"和"current 版本"的 program state（数据流 + 控制流）
3. 定位 buggy statements，从 fix 追溯找最早含所有 buggy statements 的 commit

**结果**：add-only 上 F1 +17~19% over A-SZZ；1.95s/fix。

**对我们的意义**：直接前置工作——他们已经把 ADD-only 问题当作核心挑战。我们必须对比并解释为什么 multi-form framework 比他们的程序切片更通用。

---

### 4.6 VERCATION (LLM-Enhanced Static Analysis, arXiv 2024)

> Cheng et al. **LLM-Enhanced Static Analysis for Precise Identification of Vulnerable OSS Versions.**

**核心思路**：LLM (GPT-4) + static analysis + semantic clone detection 三件套。

**方法（3 步 hybrid）**：
1. Program slicing 抽 vuln-relevant statements + LLM (Few-shot + CoT) refine 特征
2. **Expanded AST 做 semantic-level clone detection** 找 vic (vulnerability-introducing commit)
3. 在 vic 和 patch commit 之间确定 vulnerable 版本

**结果**：
- 自己的 dataset（11 项目 / 74 CVE / 1013 versions）：F1 = **92.4%**
- 找到 134 个 NVD 错误，28.61s/CVE
- Study 在 1128 CVE 大 benchmark 上重测下降到 < 45%

**对我们的意义**：第一个把 LLM 引入这个任务的 tracing 工作；用了 4 维度里的存在 + 语义。但它的 "LLM 帮忙" 是 prompt-based，不是 agent。

---

### 4.7 LLM4SZZ（ISSTA 2025）

> Tang, Liu, Liu, Yang, Bao. **LLM4SZZ: Enhancing SZZ Algorithm with Context-Enhanced Assessment on Large Language Models.**

（浙大 Bao 组的延续工作）

**核心思路**：明确指出 4 个 SZZ 限制——忽略 commit message / 假设只有 deleted lines / 忽略未改动 context / 选 BIC 靠启发式——用 LLM 解决。

**方法**：两种策略
1. **Context-enhanced identification**：给 LLM 大 context + commit message，让它从候选集选 BIC
2. **Rank-based identification**：让 LLM 从 fix 选 buggy statements 并按 root cause 相关性排序

**结果**：F1 +6.9%~16% over baselines。

**对我们的意义**：是 LLM agent 出现前的"LLM-pipeline"代表。Backbone 用 llama3.1-70b（study 里的设置）。它跟 AgentSZZ/SZZ-Agent 比已经被超越。

---

### 4.8 ReDeBug（S&P 2012）

> Jang, Agrawal, Brumley. **ReDeBug: Finding Unpatched Code Clones in Entire OS Distributions.**

**核心思路**："programmers should never fix the same bug twice" —— 但他们会，因为复制粘贴。

**方法**：
- token n-gram → hash → 在目标代码扫匹配 hash → 用 exact string match 确认
- 三大性质：scalable（2.1B LoC / 3 小时）/ 语言无关 / 零假阳

**结果**：找到 15,546 unpatched clones / 376 Debian/Ubuntu patches。

**对我们的意义**：matching 系奠基，纯语法匹配，重构就失效。后续所有 matching 工作都引它。

---

### 4.9 VUDDY（S&P 2017）

> Kim, Woo, Lee, Oh. **VUDDY: A Scalable Approach for Vulnerable Code Clone Discovery.**

（韩国 Korea U / Heejo Lee 组奠基作）

**核心思路**：函数级 hash + length-filtering，把 clone detection 做到极致 scalable。

**方法**：
- 对每个 function：parse → normalize/abstract（变量名等）→ hash → signature
- 跟漏洞函数库比 hash
- length filter 避免每两个函数都比

**结果**：1B LoC 预处理 14 小时，单项目秒级。数据库 5664 vulnerable functions / 9770 patches / 1765 CVEs。

**对我们的意义**：matching 系最被引用的代表；只能扛轻微 abstraction，重重构就失效。

---

### 4.10 MVP（USENIX Sec 2020）

> Xiao et al. **MVP: Detecting Vulnerabilities using Patch-Enhanced Vulnerability Signatures.**

**核心思路**：同时用 vulnerability + patch signature（关键创新——之前只用一种）。

**方法**：
- Program slicing 在 syntactic + semantic 层抽两种 signature
- 判定：函数匹配 vuln signature **且** 不匹配 patch signature → vulnerable

**结果**：找到 97 个新漏洞 / 23 个 CVE。

**对我们的意义**：早期"用 patch 信息"的代表，启发了 MOVERY/V1SCAN/Vision 这一线。**已经在用我们说的"存在 + 缺失"两类特征**。

---

### 4.11 MOVERY（USENIX Sec 2022）

> Woo, Hong, Choi, Lee. **MOVERY: A Precise Approach for Modified Vulnerable Code Clone Discovery from Modified Open-Source Software Components.**

（Korea U / Heejo Lee 组延续）

**核心思路**：处理"被修改过的"vulnerable code clone（91% 真实 VCC 跟 disclosed vuln 语法不同）。

**方法**：
- 用**最早的** vulnerable function（不是 disclosed 那个）
- 抽 **core vulnerable lines + patch lines** 作为 signature
- 判定：函数匹配 vuln signature **且** 不匹配 patch signature → VCC

**结果**：96% precision / 96% recall，发现的 VCC 数比 ReDeBug/VUDDY 多 2.5 倍。

**对我们的意义**：解决了 VUDDY 重构敏感的痛点。但仍是 matching paradigm，对 ADD-only 等场景仍受限。

---

### 4.12 V1SCAN（USENIX Sec 2023）

> Woo, Choi, Lee, Oh. **V1SCAN: Discovering 1-day Vulnerabilities in Reused C/C++ Open-source Software Components Using Code Classification Techniques.**

（Korea U / Heejo Lee 组延续——VUDDY → MOVERY → V1SCAN）

**核心思路**：**Hybrid**——version-based + code-based 协同。

**方法**：**Code classification** 区分目标项目中"实际使用的"vs"未使用的"OSS 代码，只考虑前者。

**结果**：比 SOTA 多发现 50% 漏洞，FP 71% → 4%，FN 33% → 7%。

**对我们的意义**：在 matching 系里第一次明确说"version + code 两种信息要结合"，跟我们 multi-form 的初步 motivation 接近。

---

### 4.13 Vision（ASE 2024）

> Wu et al. **Vision: Identifying Affected Library Versions for Open Source Software Vulnerabilities.**

**核心思路**：针对 **Java/Maven** library 的 affected library version (ALV) 识别。

**方法（关键创新）**：
- 用 Maven registry 不用 GitHub（下游 consumer 视角准确）
- **Weighted IPDG**（Inter-Procedural Dependency Graph）+ HITS 算法选关键 method
- 同时生成 vulnerability + patch signature
- **专门处理 ADD-only**：用 added lines 生成"vulnerability-potential signature"

**结果**：P=0.91 / R=0.94，比 SOTA 提升 +12.3% P / +154.1% R。

**对我们的意义**：在 matching 路线里**首次**系统性处理 ADD-only。但他们仍然是函数粒度的 graph 匹配，不是抽象到我们 multi-form 框架的高度。Java/Maven 限定也是局限。

---

### 4.14 FIRE（USENIX Sec 2024）

> Feng, Wu, Xue, Pan, Zou, Liu, Jin. **FIRE: Combining Multi-Stage Filtering with Taint Analysis for Scalable Recurring Vulnerability Detection.**

**核心思路**：Multi-stage filtering + taint analysis for SCALABLE recurring vuln detection。

**方法**：3 阶段过滤（Simple feature → Lexical → Syntactic）+ 最后 taint analysis；核心 signature 是 vulnerability function 与 patch function 的 **differential tainted paths**。

**结果**：298/385 recurring vulns，比 VUDDY 多 31.4%，比 MOVERY 多 47%。

**对我们的意义**：⚠️ **它说的 "multi-stage" ≠ 我们的 "multi-form"**——它是同一种特征的多阶段过滤，我们是不同种特征的多形式融合。论文里要明确区分，否则审稿人会质疑"FIRE 不也是多阶段吗"。

---

### 4.15 AFV / Precise (Un)affected Web（ASE 2022）

> Shi, Zhang, Luo, Mao, Yang. **Precise (Un)Affected Version Analysis for Web Vulnerabilities.**
> (Tool name: AFV = AFfected Versions)

**核心思路**：**Vulnerability-centric**（区别于 patch-centric）。

**核心 insight**（跟我们最像的）：现有方法假设"patch 只含 vuln-relevant changes 且必有 deletion lines"——这个 **inappropriate patch assumption** 是失败根因。

**方法**：从 patch 抽取**vulnerability logic**，直接用 logic 检查每个版本是否含此 logic。

**限定**：PHP web vulnerabilities，34 CVE / 299 versions。

**结果**：P=98.15% / R=85.01%。

**对我们的意义**：⚠️ **是我们 framing 的最强先验工作**！他们已经讲过"patch assumption 是问题"和"vulnerability logic"。我们必须明确区分：他们针对 PHP web，方法是 PHP-specific 静态分析；我们是通用 C/C++ 框架，并把 4 维度系统化。如果不区分清楚，novelty 会被质疑。

---

### 4.16 Vul4Java（ASENS 2024）

> Wang, Hu, Zhou, Tambadou, Zuo. **Vul4Java: A Java OSS vulnerability identification method based on a two-stage analysis.**

⚠️ **注意**：这是你下错的 PDF。Study 里的 **Verjava (Sun et al, ICSME 2022)** 不是这一篇。

**核心思路**：Java OSS 漏洞识别，两阶段。
1. Vulnerability Association：建 Java OSS ↔ vuln 数据库映射（1013 CVE / 266 OSS）
2. Vulnerability Verification：static analysis 抽 Structure-Aware Call Graph (SACG) → 定位漏洞函数 → 对比 patch 前后 code feature 相似度

**结果**：F1 = 0.779（7 项目 / 167 vuln info）。

**对我们的意义**：Java-specific，跟我们 C/C++ 任务相关性弱。建议补回真正的 Verjava。

---

### 4.17 He et al. — Patches + Developer Logs（TDSC 2024）

> He, Wang, Zhu, Wang, Zhang, Li, Yu. **Automatically Identifying CVE Affected Versions With Patches and Developer Logs.** IEEE TDSC 2024.

⭐⭐ **跟我们任务最像的工作**

**核心 insight**：
- **Repatching**：未打 patch 的代码不一定漏（可能用别的方式修了）
- **Partial matching**：早期版本经多次更新，patch 没法 exact match

**方法**（per CVE 3 步）：
1. 用 patch + developer logs 确定 trunk 的 last vulnerable version
2. 对每个 branch 同样处理
3. early versions 用 partial matching

**关键技术**：
- 用 **version tree** 结构（trunk + branches）
- **同时用 `-` lines + `+` lines + `oth` (context lines)**——这跟我们说的 multi-form 思路接近！
- exact match vs partial match

**结果**（仅 Linux Kernel）：P=94.3% / R=95.6%；纠正 NVD 的 2497 FP + 9330 FN。

**Study 没收录的原因**：用了 developer logs（非纯代码信号），study 限定纯代码。

**对我们的意义**：⚠️⚠️ **最强直接竞争对手**。他们已经在工程上把多种信号集成了，但是**作为工程技巧而非框架**。我们的 multi-form representation 是 principled framework，He et al. 是 ad-hoc 集成。我们要正面对比，说明 He et al. 是我们框架的一个不完整 instance（缺 PHP 专用的 vuln logic 维度，缺 LLM agent 维度）。

---

### 4.18 Study 本身（arXiv 2025-09）

> Chen, Liu, Cao, Xiao, et al. **Vulnerability-Affected Versions Identification: How Far Are We?** arXiv:2509.03876v2.

**贡献**：
1. 构建 1128 CVE / 132 CWE / 9 个 C/C++ 项目的 manually curated benchmark（投入 0.5 人时/CVE）
2. 系统性评估 12 个代表性工具（6 tracing + 6 matching）
3. 4 个 RQ：effectiveness / 根因分析 / patch-type 敏感性 / 工具组合

**关键发现**：
- 没有任何工具 accuracy > **45%**
- ensemble 也只能 < 60%
- **add-only patches、cross-file changes、multi-branch development** 显著降低性能
- FP/FN 主要来自启发式过度依赖、语义建模不足、匹配僵化

**对我们的意义**：我们的 benchmark + baseline 全部以这篇为锚。我们的 paper 必须正面回答 study 提出的问题。**study 的发现就是我们的 motivation**。

---

### 4.19 AgentSZZ（arXiv 2026）

> Lyu, Shi, Kang, Widyasari, He, Niu, Yang, Chen, Yang, Lawall, Lo. **AgentSZZ: Teaching the LLM Agent to Play Detective with Bug-Inducing Commits.**
> （SMU David Lo 组）

**核心思路**：把 BIC 识别从"固定 pipeline"升级为"LLM agent 自主探索"。

**关键 insight**：blame-based 方法对 ghost commits (17%) + cross-file cases (7%) 完全失效（约 25% 的 BIC 不可追踪）。

**架构**：3 阶段 — Preprocessing / ReAct Loop (≤15 turns) / Output

**5 个工具**：git_show, git_blame, git_log_s (pickaxe search), git_log_func, git_grep —— 跟我们 `agent_tools.py` 几乎一样

**Backbone**：GPT-5-mini

**结果**：F1 比 LLM4SZZ +27.2%，cross-file recall +300%。

**对我们的意义**：⚠️⚠️ **跟我们 Phase 2 Step 2 思路高度重合**。他们已经发表，"用 LLM agent 做 vulnerability tracing"不再是空白。但他们输出 BIC commit，不是 V_aff 版本集合。我们的差异点必须在 framework 层面，而非"也用 agent"。

---

### 4.20 SZZ-Agent / How and Why Agents（arXiv 2026）

> Risse, Böhme. **How and Why Agents Can Identify Bug-Introducing Commits.** MPI-SP.

**核心思路**：SZZ 拿了 2026 ACM SIGSOFT Impact Award，但 20 年来 SOTA 仅 0.64 F1 (LLM4SZZ)。Agent 能不能突破？

**SZZ-Agent — 2 阶段**：
- **Stage 1**：fix 有 deleted lines 时走 SZZ：标准 SZZ 出 candidates，agent 从中选最早的 BIC
- **Stage 2**（**关键**）：处理 ADD-only / Stage 1 失败时——**对 fix 修改的文件做 binary search 历史**，agent 在每个中点读完整文件内容 + commit message + diff，判断 bug 是否已存在

**Simple-SZZ-Agent**（更精简版）：跳过 binary search，agent 直接把 fix 压缩成 greppable patterns 去候选集 grep——token 成本降 43% 但 F1 反而更好。

**5 个 ablation studies**：data leakage / LLM backbone / context / Stage 1 vs 2 / 阈值参数。

**结果**：F1 = **0.81 on Linux**（+17 pts vs LLM4SZZ 的 0.64，+27 pts vs SZZ 0.54）。

**新 dataset DS_LINUX-26**：fix commits in Sep 2025 - Jan 2026（**LLM 训练 cutoff 之后**，避免 data leakage）。

**对我们的意义**：⚠️⚠️ **Stage 2 binary search 正好解决我们说的 ADD-only 问题**——我们的 multi-form representation 在 ADD-only 维度上已被部分预占。**我们 paper 必须有 SZZ-Agent 作为 baseline**，否则审稿人会质疑。优势点：他们仍然只输出 BIC commit，不是 V_aff 版本集合；BIC → V_aff 还需 V-SZZ 那种 commit→version 转换。我们直接做 V_aff，省去这个 mapping 步骤。

---

## 五、总结观察 — 写论文时该怎么用这份整理

1. **没人提出系统的 4 维度框架**——各家都在 ad-hoc 组合。这是我们的 novelty 落点。

2. **AFV [ASE'22]** 已经讲过 "patch assumption 是问题"——必须区分清楚。我们要说："他们指出问题但限于 PHP 专用，我们提出通用 C/C++ 框架并把 4 维度系统化。"

3. **He et al. [TDSC'24]** 最像我们——但作为工程而非框架。我们要说："他们 ad-hoc 集成多信号；我们提供 principled 4 维度框架；他们是我们框架的不完整 instance。"

4. **Vision [ASE'24]** 用了 IPDG + 加 lines 处理 add-only——matching 路线里的标杆。

5. **AgentSZZ + SZZ-Agent [arXiv'26]** 是 LLM agent 直接竞争对手——但都输出 BIC commit 而非 V_aff。我们要明确：BIC → V_aff 需要额外步骤（V-SZZ 那种映射），我们直接做端到端。

6. **Korea U / Heejo Lee 组（VUDDY → MOVERY → V1SCAN）** 是 matching 路线最连贯的演进，注意他们的引用关系。

7. **浙大 Lingfeng Bao 组（V-SZZ → SEM-SZZ → LLM4SZZ）** 是 tracing 路线最活跃的团队，研究 trajectory 一脉相承。

8. **2026 是 LLM agent 时代起点**——我们如果赶在 ICSE'27 或 USENIX'27 投稿，要承认两篇 agent paper 已存在，并明确 differentiate。
