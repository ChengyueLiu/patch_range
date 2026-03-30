# VARA: Vulnerability Affected Range Analyzer

## 问题定义

给定项目 P 的 git 仓库和漏洞修复 commit，识别 P 的所有发布版本中哪些受该漏洞影响。

形式化：已知修复 commit set F，版本 tag 集合 V = {v1, v2, ..., vn}，求 Vaff ⊆ V。

## 现有方法的失效原因分析

根据 [Vulnerability-Affected Versions Identification: How Far Are We?] 对 12 个工具的系统性评估（1,128 CVE，9 个 C/C++ 项目），现有方法存在以下系统性缺陷：

### Tracing 类方法的失效原因

Tracing 方法从 fixing commit 出发，通过 git blame 回溯找到引入漏洞的 commit（VIC），再推断中间版本为受影响版本。各阶段的失效原因：

**S1 - 漏洞语句选择**：大多数工具（V-SZZ、VCCFinder、Lifetime、TC-SZZ）依赖简单启发式，仅关注 deleted lines 或其相邻行。当 patch 跨多函数或多文件时，无法区分语义相关和不相关的改动。论文对 100 个样本分析显示，49 个 patch 涉及多函数/多文件修改，其中 16 个包含无关 hunk。即使 LLM 辅助（LLM4SZZ），仍有 35% 的失败率。

**S2 - Commit 回溯**：大多数工具仅做单步 blame，但 100 个样本中只有 70 个可通过单步追溯到 VIC，30 个需要多步。V-SZZ 的迭代追溯基于相似度启发式，100 个样本中 16 个过度追溯、12 个追溯不足。

**S3 - VIC 选择**：候选 commit 中选择最终 VIC 的策略（最早 commit、最多 blame commit 等）均为启发式，未验证所选 commit 是否真正引入了漏洞。LLM4SZZ 用 LLM 做语义验证，但 100 个样本中仍产生 12 个 FP 和 29 个 FN。

**S4 - 版本推断**：多分支开发环境中，同一漏洞可能在不同分支独立修复。仅分析 main 分支的工具会遗漏其他分支的受影响版本。V-SZZ 支持跨分支 patch 检测，但其简单匹配策略在 100 个样本中有 13 个未能检测到重复 patch。

### Matching 类方法的失效原因

Matching 方法从 patch 中提取漏洞特征（签名），在目标版本中搜索匹配。失效发生在两个阶段：

**S1 - 签名构造**：
- **粒度问题**：ReDeBug 用滑动窗口 token 序列、VUDDY 用整个函数体作签名，过于粗粒度，对不相关代码改动敏感。MOVERY 和 FIRE 提取语义相关语句，但对不同 patch 类型采用统一提取规则，论文分析 47 个样本中特征提取不正确。
- **删除行假设**：Movery、V1SCAN、FIRE、VULTURE 假设 patch 中 deleted lines 必须存在于目标版本。数据集中 55.8% 的可删除行漏洞因此被忽略。

**S2 - 签名匹配**：
- **精确匹配脆弱**：大部分工具依赖精确匹配（hash 或 token 完全一致），代码重构、变量重命名即失效，导致高 FN。
- **近似匹配引入 FP**：V1SCAN（LSH）、FIRE（相似度阈值）放松匹配条件后，将结构相似但语义无关的函数误判为漏洞。VUDDY 的函数级签名在两种场景产生 FP：(1) patch 改变函数结构后旧签名匹配到重构后的代码；(2) 旧版本中存在结构相似的不同函数。

### 总结
                                                                                                                                                                                                                                                         
Matching 召回失败的原因：                                                                                                                                                                                                                                
   
1. 代码演化：变量重命名、代码重构、函数拆分/合并后，精确匹配失效                                                                                                                                                                                         
2. 删除行假设：假设 patch 中的 deleted lines 必须存在于目标版本，add-only patch 直接无法处理                                                                                                                                                           
3. 签名粒度不当：函数级签名太粗（无关改动导致 hash 不同），语句级又太细（微小格式差异就失配）                                                                                                                                                            
                                                                                                                                                                                                                                                           
  Tracing 召回失败的原因：                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                           
1. 单步 blame 不够：30% 的漏洞需要多步追溯才能找到引入 commit                                                                                                                                                                                            
2. add-only patch：没有 deleted lines 就无法启动 blame
3. 漏洞语句选择错误：启发式选错了要追溯的代码行，导致追到无关 commit                                                                                                                                                                                     
4. 单分支局限：只看 main 分支，遗漏其他分支的受影响版本
### 共性问题

**Noisy patch**：19% 的 patch 包含与漏洞无关的改动（重构、多 issue 修复），污染特征提取和 blame 追溯。

**语义鸿沟**：patch 的修改位置（fix location）与漏洞根因（root cause）之间存在语义断裂。double free、use-after-free 等漏洞涉及跨函数/跨文件的过程间交互，单一函数内的代码匹配或 blame 追溯无法捕获。

**存在性验证缺失**：现有工具仅判断"漏洞特征是否存在"或"该 commit 是否引入了漏洞"，但未验证目标版本中该漏洞是否真正可触发。Tracing 方法易误选 VIC，matching 方法在找到签名匹配后未验证上下文是否构成漏洞。

### 量化结果

| 方法 | 最佳 Accuracy | 最佳 Recall | 最佳 F1 |
|-----|-------------|-----------|---------|
| Tracing 最佳（VCCFinder） | 44.9% | 76.6% | 77.8% |
| Matching 最佳（ReDeBug） | 37.0% | 60.7% | 72.5% |
| Ensemble 最佳 | 55.0% | — | 84.8% |

没有任何单一工具 accuracy 超过 45%，ensemble 后仍低于 60%。

## 研究动机

现有方法的根本问题：**matching 和 tracing 各自存在系统性盲区，且二者的优势互补**。Matching 擅长精确验证代码是否存在但不容忍代码变化，tracing 不惧代码演化但版本范围推断粗糙。现有工作要么只用一种，要么简单投票组合，未充分利用二者的互补性进行交叉验证。

VARA 的核心思路：**先用双通道（matching + tracing）最大化召回，再通过交叉验证和分阶段过滤消除误报**，从而同时实现高 recall 和高 precision。

## VARA 方法

### 核心思路

两阶段 pipeline：**高召回粗筛 → 精准过滤**。

- 阶段一：用宽松策略将 recall 拉到接近 100%，不关心误报
- 阶段二：分析误报类型，规则可解的用规则，语义层面的用 LLM

### 阶段一：双通道召回

Matching 和 Tracing 两个通道并行，结果取 union。

#### 通道 1：Matching

从 fixing commit 解析 diff，提取每个文件的 deleted lines（漏洞代码）和 added lines（修复代码）。对每个版本 tag，用 `git show tag:file` 读取文件内容（无需 checkout），检查：

- deleted lines 是否存在（漏洞代码仍在）
- added lines 是否不存在（修复尚未应用）

任一条件成立 → 标记为 affected。

匹配细节：
- **空白归一化**：strip + 多空格压缩，容忍缩进差异
- **上下文感知**：added lines 的检查限定在 hunk context 定位的代码区域内，避免同名行在文件其他位置引发误判
- **路径回退**：文件在旧版本中路径不同时，按文件名搜索候选路径，选路径后缀最相似的
- **编码容错**：UTF-8 解码使用 `errors=replace`

#### 通道 2：Tracing

1. 对 fixing commit 的每个 patched file，用 `git blame` 追溯 deleted lines（或 context lines，针对 add-only patch）找到引入漏洞的 commit
2. `git tag --contains introducing_commit` 得到所有包含该 commit 的 tag
3. 减去 `git tag --contains fixing_commit`
4. 剩余即为 affected versions

Tracing 覆盖 matching 无法处理的场景：add-only patch、代码重构后行级匹配失效、文件路径彻底变更。

#### 预过滤

在获取 tag 列表时过滤非正式发布 tag（dev、rc、beta、alpha、内部标记、backup refs 等），减少无效计算和误报。

#### 交叉验证

Tracing 通道标记的版本，如果 matching 通道明确判定为"已修复"（文件存在、修复代码完整、漏洞代码不存在），则排除。解决 tracing 因 `git tag --contains` 不区分分支导致的版本范围溢出问题。

### 阶段二：精准过滤（待实现）

对阶段一输出中的 false positives 进行分类处理：
- 规则可判定的（如版本号范围约束）→ 程序过滤
- 语义层面的（代码重构、逻辑等价变换）→ LLM 判断

## 评估

### Benchmark

采用论文公开的 benchmark：1,128 个 CVE，覆盖 9 个 C/C++ 项目、132 种 CWE 类型、59,187 个受影响版本。

### 指标

- **Version-level**：Precision、Recall、F1
- **Vulnerability-level**：Accuracy（精确匹配率）、No-Miss Ratio（不漏报率）

### 目标

Precision 和 Recall 双 95%+，F1 超过现有最佳方法（77.8%）。

## 工程设计

```
vara/               # 工具（不依赖 benchmark）
  analyzer.py       # 对外 API: analyze(repo_path, commits) -> List[str]
  repo.py           # Git 操作封装（含缓存）
  patch_parser.py   # 解析 fixing commit diff
  matcher.py        # Matching 通道
  tracer.py         # Tracing 通道
  tag_filter.py     # Tag 预过滤

evaluation/          # 评估框架（不依赖具体工具）
  interface.py       # 数据类型、EvaluationConfig、ToolCallable
  evaluator.py       # Evaluator 类，三步独立（run / compare / metrics）

run_evaluation.py    # 启动脚本
```

工具接口：`analyze(repo_path: str, commits: List[str]) -> List[str]`

评估器通过 `ToolCallable` 类型解耦，可替换任意工具实现。评估结果按时间戳存储，不覆盖历史。
