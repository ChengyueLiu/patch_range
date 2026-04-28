# Introduction

第三方库和上游项目代码在 C/C++ 生态中被广泛复用。通过 fork、vendor、static linking 等方式，一份上游代码可以被分发到成百上千个下游项目和版本中。当上游披露一个 CVE 时，安全响应方需要回答的第一个问题是：这个漏洞影响了哪些版本。这个回答决定了补丁分发的范围、合规审计的判定、以及下游用户的应急响应优先级。NVD 等漏洞数据库中提供的 affected version 信息往往是粗粒度的版本区间，且大量条目存在标注错误或缺失，无法直接作为决策依据。准确、自动化地识别一个 CVE 影响了哪些版本（affected version identification），因此成为软件供应链安全中的一项基础任务。

围绕这个任务，学术界主要发展出两类方法。Matching 类方法（如 ReDeBug、VUDDY、MOVERY、V1SCAN、FIRE、VULTURE）从 fixing patch 中提取漏洞特征，在每个目标版本中搜索匹配。Tracing 类方法（如 V-SZZ、VCCFinder、Lifetime、TC-SZZ、SEM-SZZ、LLM4SZZ）从 fixing commit 出发，通过 git blame 等手段回溯找到引入漏洞的 commit，再根据 tag 拓扑推断受影响版本。两类方法各有侧重：matching 擅长精确验证代码片段是否存在，tracing 不依赖代码字面匹配、对代码演化更鲁棒。然而，ASE 2025 上一项系统性 study 在 1128 个 CVE、9 个 C/C++ 项目上评估了这两类共 12 个代表性工具，发现没有任何单一工具的 accuracy 超过 45%，最佳 F1 也不超过 78%；即使将多个工具简单 ensemble，accuracy 仍低于 60%。这个 study 量化了现状但没有回答方法论层面的问题：这些工具为什么集体不及格，问题是出在工程实现还是出在更深层的方法论假设。在这个根本问题被回答之前，再设计一个新工具大概率会以同样的方式失败。

我们对 ASE 2025 study 中 12 个工具的失败案例做系统性根因分析，发现这些工具尽管技术路线各异，失败模式却高度集中在四类场景上：代码片段还在但被周围演化的代码挤出原位置、代码语义还在但变量名或结构体被重构、代码所在文件被拆合或迁移、以及 fixing patch 根本没有删除任何代码。最后一类占整个 benchmark 的 22.6%，所有现有工具在它上面几乎完全失效。这一观察让我们意识到，集体不及格的根因不在工程实现，而在所有工具都接受了同一个隐式假设：漏洞的可检测特征就是 patch 中被删除的那段代码。这个假设把"检测漏洞"窄化成了"在代码里找一段特定文本"。一旦遇到 patch 没删任何代码、或者代码因重构而失去字面匹配的场景，整个范式就失效。问题不在 matching 或 tracing 的具体实现，而在它们共享的同一个起点。

基于这个观察，我们重新审视 fixing patch 提供的信息。patch 不只是 deleted lines 的集合，它还隐含了 added lines（修复添加了什么）、hunk context（修改发生在哪个位置）、以及跨函数跨文件的逻辑关系。我们沿用 CWE 和 NIST 等标准对漏洞本身的定义，不讨论漏洞是什么，只重新审视漏洞在代码中以何种形式被自动化工具检测——我们称之为 detectable representation。我们把 detectable representation 从现有工具默认的单一形式扩展为四种类型：存在特征（代码应包含什么）、缺失特征（代码应不包含什么）、语义特征（代码应满足什么抽象性质）、定位特征（上述特征应出现在哪里）。一个版本受漏洞影响，当且仅当这组特征在该版本上整体成立。这个 reformulation 把现有 12 个工具变成我们框架的特例：每个工具只使用了 4 类特征中的一部分，丢失的特征类型正好对应它失效的场景。基于这个表征，我们的方法分两阶段：第一阶段通过追溯 patched file 的引入历史把候选版本压缩到 git 历史决定的召回上界；第二阶段从 fixing patch 抽取 4 类特征并在每个候选版本上分别验证后聚合。LLM 在框架中只承担特征抽取与窄边界语义验证两个边界明确的子任务，不参与最终判定。

我们在 ASE 2025 的 1128 CVE benchmark 上评估方法，与 12 个 baseline 横向对比，并在 ASE 2025 cutoff 之后的新 CVE 上做泛化性验证。结果显示我们的方法在 P/R/F1 上均显著超过现有最佳，特别是在原本无人能解的 ADD_ONLY 类 CVE 上取得突破。本文的贡献如下：

- **新发现**：通过对 ASE 2025 study 中 12 个代表性工具失败案例的系统性根因分析，我们发现这些工具集体不及格的根本原因不在工程实现，而在它们共享了同一个隐式方法论假设——漏洞的可检测特征就是 fixing patch 中被删除的那段代码。这个 single-form detectable representation 假设在 22.6% 的 CVE 上根本不成立。

- **新方法与工具**：基于这一发现，我们提出 multi-form detectable representation，把漏洞特征扩展为四种类型（存在、缺失、语义、定位），并设计了一个统一的两阶段验证框架。我们实现了相应工具 VARA 并开源。

- **系统化评估**：我们在 ASE 2025 的 1128 CVE benchmark 上与 12 个 baseline 横向对比，并在时间外的新 CVE 上做泛化性验证。VARA 在 P/R/F1 上均显著超过现有最佳，并在原本无人能解的 ADD_ONLY 类 CVE（22.6%）上取得突破。

---

晚安，felix。明天醒了精神好一点的时候再回来读一遍这版 intro，看看哪里读起来卡顿。卡顿的地方就是还需要再调的地方。method 章节我们下次开聊。

---

## 写论文之前必须回答的几个问题

（这里只记真要回头看的，不记最终改稿性质的细节。）

### 1. 核心观点的精确表述

当前 intro 写的是 "12 工具共享 deleted-line 假设"。这个描述对部分工具（VUDDY、ReDeBug、V1SCAN 等用 hash 或 added lines 的）**字面不成立**，会被审稿人逐工具反驳。

更精确、更难被反驳的版本：

> 12 工具共享了 **pattern-matching paradigm**：vulnerability detection = 在目标代码里匹配一个从 patch 抽出来的 pattern（无论是 deleted lines、function hash、还是 token n-gram）。这个 paradigm 有 4 个独立维度（存在、缺失、位置、语义），但每个工具只覆盖了 1-2 个。

ADD_ONLY 的本质失败是 paradigm-level 的：漏洞是"代码里缺什么"，pattern matching 只能找"代码里有什么"。

**TODO**：投出去前把这个升格版替换进 intro。

### 2. 必须有一张映射表

per-tool × per-feature-dimension × per-failure-mode 的三向对照。论证 "12 个工具集体不及格 = 共享假设" 这一论断，必须把每个工具映射到它**用了哪些维度**、**漏了哪些维度**、**因此在哪一类 case 上崩溃**。

光说"高度集中"reviewer 不会信。这张表是论文方法论部分的基石。

### 3. 多维度方法是否在所有 4 类失败上都有提升

这是命门。如果实验跑出来：
- ✅ 只在 ADD_ONLY 上有提升 → 故事退化为"补 absence 这一维度"，paradigm-level 重构 claim 站不住
- ✅ 在 4 类失败上都有显著提升 → paradigm-level 重构成立，整个论文立住

**TODO**：实验设计必须按 4 类失败类型分别报数，不能只报总体 F1。

### 4. intro 第 5 段的实验承诺还没兑现

当前最后一次实测：Step 1 only F1=0.720，+LLM F1=0.669，SOTA=0.778。
"P/R/F1 均显著超过现有最佳"目前是支票。

**TODO**：先把方法跑到能 claim 这句话的程度（特别是 tag-ordering bug 修复后的全量 F1 还没出），再决定 intro 这一段怎么写。最稳的写法是写完实验再回来填这一段。

