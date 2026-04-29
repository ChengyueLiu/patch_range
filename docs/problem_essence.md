# 问题本质与现有方法失败的真正原因

本文档把"vulnerability-affected version identification"这个任务的本质讲清楚。
目标读者：第一次接触这个任务的人。

---

## TL;DR（三句话）

> **问题本质**：判断版本 V 是否受 CVE 影响 = 检查 V 是否仍**缺**修复漏洞所需的语义。这是个**语义对齐检查**问题。
>
> **为什么现有方法不生效**：现有方法都用 syntactic（文本匹配、commit hash、git 拓扑）做这个语义检查的代理。代理在三种情况下失败：(1) **本可解但策略选错**，(2) **找不到要比的位置**，(3) **找到了位置但判不准**。
>
> **怎么解决**：把这三类分开对症下药——类型 1 用对的算法工程解；类型 2 用语义定位（LLM/AST/embedding 找语义等价代码）；类型 3 用语义判断（LLM 理解漏洞机理）。**不要让单一 paradigm 硬扛所有困难**——这是现有工具失败的根本姿态。

---

## 一、把问题拆成两步

判断 V 是否受影响，需要回答："V 是否对齐 fix-applied 的语义状态？"

这个回答在工程上分两步：

| 步骤 | 做什么 | 类比 |
|---|---|---|
| **(a) Locate** | 在 V 里**找到**与 fix 相关的代码段 | "知道要去哪儿看" |
| **(b) Judge** | 判断找到的代码段是 fix 前还是 fix 后状态 | "看了之后能不能下结论" |

每一步都可以用 syntactic 或 semantic 方式做。Syntactic 便宜、快、有限制；semantic 贵、准、覆盖广。

---

## 二、三分法（核心结构）

按 "locate + judge 是否能用 syntactic 完成" 把所有困难分三类：

### 类型 I：syntactic 可以解（但要选对策略）

**特征**：locate 能用 syntactic 找到，judge 能用 syntactic 给对答案。**问题不在 syntactic 的能力，在于现有工具普遍选错策略。**

| Sub-case | 现有工具的错误策略 | 选对的策略 |
|---|---|---|
| **A1** ADD-only | 用 deleted lines 当 signature → 没东西可比 | 用 **added lines** 检查 V 是否含 fix；不含即 affected |
| **A4** 多分支独立引入 | 只看主分支历史 | 用 `git log --all` enumerate 所有分支的 intro |
| **A5** cherry-pick fix | 用 commit hash 比对 | 用 **diff 内容相似度**匹配 cherry-picked fix |
| **A6** partial fix | flatten 所有 fix commits 后 AND | **group-aware logic**：每个 fix group 内 OR，跨 group AND |
| **A7** foundational vuln | SZZ-classic 假设"intro 早于 deleted lines" → 失败 | 用 **file 第一次 commit** 作为 vuln intro |

**例子**：
- **A1**：CVE-2021-3582（qemu）—— fix 给 `pvrdma_map_to_pdir` 加 length 边界检查 `length = ROUND_UP(...); if (nchunks * TARGET_PAGE_SIZE != length) return NULL;`。检查方法：看 V 上 `pvrdma_cmd.c` 是否含这段——不含即 affected。当前工具因为只看 deleted lines（这个 fix 没删任何行），全部错答 NO_VULN。
- **A4**：Apache httpd `mod_proxy_uwsgi.c` 在 trunk 和 2.4.x 分支被独立 add（不同 commit）。`git log --all --diff-filter=A` 返回两个 intro，分别覆盖各自分支的 tag。
- **A5**：OpenSSL fix 在 master 后 cherry-pick 到 1.1.1 和 1.0.2 分支，hash 不同。如果只 subtract master 的 hash，1.1.1 和 1.0.2 的 tag 全被错算 affected。

→ 这一类 A 不需要语义方法，**纯算法工程**。这一类占绝大多数。

### 类型 II：syntactic 找不到位置（locate 失败）

**特征**：fix 修的代码在 V 里**确实存在**（语义层），但**写法/位置变了**，syntactic 完全找不到。

| Sub-case | 为什么找不到 |
|---|---|
| **A2** 重构改名 | V 里同语义代码用了不同变量/函数名/写法 |
| **A3** 跨文件迁移 | V 里同语义代码在另一个文件，且常伴随重写 |

**例子**：
- **A2**：CVE-2020-35965（FFmpeg）—— fix 改 `for (y = 0; y < s->ymin; y++)`（struct 成员），但在 n0.11 版本里写成 `for (y = 0; y < ymin; y++)`（局部变量）。语义完全相同，syntactic 找不到。需要 LLM/AST 判"这个 loop 等价于那个 loop"。
- **A3**：qemu 的 USB 转发漏洞 —— fix 改 `hw/usb/redirect.c`，但在老版本里这段代码在 `usb-redir.c`（根目录）。文件路径完全不同 + 内部代码也被改写过。`git grep --fixed-strings` 完全失效。

→ 这一类**必须用语义定位**：用 LLM / AST diff / embedding 找"V 里跟 fix 中相关代码语义同源"的位置。

### 类型 III：syntactic 找到了但判断错（judge 失败）

**特征**：locate 顺利完成，但**根据找到的信息做出的 syntactic 判断是错的**——因为判断需要理解"V 是否真的 vulnerable"，而不是"V 文本上像不像 fixed"。

| Sub-case | 为什么判错 |
|---|---|
| **file 比 vuln 早** | V 里有 fix 改的那个文件，没有 fix → syntactic 说 affected。但 V 上根本没 vulnerable feature，因为该 feature 是后来某个 commit 加进 file 的 |
| **A1.b** ADD-only 子情况 | V 没有 fix 加的那一行（检查），但 V 已通过 macro 或别的形式实现等价保护 |
| **#ifdef'd 代码** | V 含 vulnerable code，但被 build flag 禁用，实际 unreachable |

**例子**：
- **file 比 vuln 早**：CVE-2022-4203（OpenSSL）—— fix 改 `crypto/x509/v3_ncons.c`，处理 `NID_id_on_SmtpUTF8Mailbox` 相关的 X.509 name constraint 校验。但 SmtpUTF8Mailbox 是 RFC 8398（2018 年）的概念，OpenSSL 1.0.0（2010 年）根本没这个 feature。syntactic 看：file 在 1.0.0 存在 → 不含 fix → 算 affected。但实际：1.0.0 没漏洞特征。在我们的实测里这个 case 产生 `dist=-141` 的巨型 EARLY 误报。
- **CVE-2022-1114（ImageMagick）**：fix 改 `coders/dcm.c` 的 `DCMInfo->scale` 处理。但在 v7.0.10-30 上，那段 scale allocation 的代码根本不存在——是后来某个 commit 才加的。syntactic：file 存在 → 算 affected。实际：v7.0.10-30 没 vulnerable code。

→ 这一类**必须用语义判断**：让方法能回答"V 是否真的含 vulnerable feature"，而不是只看"V 是否含 fix 文本"。

---

## 三、A1-A7 + file比vuln早 的完整 mapping

| 困难 | 类别 | 说明 |
|---|---|---|
| A1 ADD-only | **I** | 选对策略（用 added lines）即解；现有工具策略选错 |
| A2 重构改名 | **II** | 严重重写时 syntactic 必死；轻度变动可降到 I |
| A3 跨文件迁移 | **II** | 跨文件 + 内容改写时 syntactic 必死 |
| A4 多分支独立引入 | **I** | 用 `--all` 即解 |
| A5 cherry-pick fix | **I** | 用 diff content 相似度匹配即解 |
| A6 partial fix | **I** | 用 group-aware logic 即解 |
| A7 foundational | **I** | 用 file_intro 即解 |
| **file 比 vuln 早** | **III** | 必须语义判断"V 是否含 vulnerable feature" |

**重要观察**：**5/7 的 A 类困难本质是 Cat I**——是工程问题，不是 syntactic 范式的局限。
真正必须语义化的，只有 A2、A3（locate 阶段）和"file 比 vuln 早"（judge 阶段）。

---

## 四、为什么现有工具失败

每个现有工具都对**部分** A 类做了努力，但**没有任何一个工具同时把三类都解开**：

| 工具 | 主攻方向 | 真实覆盖 |
|---|---|---|
| V-SZZ | A2/A5 用相似度 | 解部分 I（A5 用 cross-branch reuse）+ 部分 II（A2 用 line mapping） |
| SEM-SZZ | A1 用程序切片 | 解 I 类的 A1 但只对程序切片能识别的逻辑 |
| LLM4SZZ | 用 LLM 选 statement / commit | 解 I 类 A1 部分；语义层未深入 |
| AgentSZZ | LLM agent 探索 | 主攻 II 类的 A3，但目标是 BIC（不是 affected version） |
| 我们的 Layer 1 | trace + cross-file grep | 解全部 I 类（多数），II 类的 A3 部分（grep 能找到的），III 类不解 |

**所有工具的共同失败模式**：把 syntactic 当万能锤，**用同一个 paradigm 同时硬扛 I/II/III 三类困难**。
- 工具们在 Cat I 上反复"打补丁"（每个 A 加一个 syntactic 启发式），覆盖永不完整
- Cat II/III 几乎没人正面处理，因为不引入语义就没法处理

→ 这是 study 测出"无单工具 > 45% accuracy"的根本原因。

---

## 五、关键 takeaway

```
本质      : V 是否含 fix 语义（语义对齐检查）
代理失败  : 三种 — 选错策略 / 找不到 / 判不准
解决路径  :
  Cat I   → 算法工程（每个 sub-case 选对策略）
  Cat II  → 语义定位（LLM 找语义等价代码）
  Cat III → 语义判断（LLM 理解漏洞机理）
原则      : 让 syntactic 解 syntactic 问题，让 semantic 解 semantic 问题
          不要一个 paradigm 硬扛所有
```

---

## 六、已知 gap 和边界 case（写论文要 scope 的）

1. **GT 本身错**：上游漏洞数据库（NVD 等）有 5-30% 的标注错误。任何方法都受影响，应单独 quantify。
2. **A2 / A3 是连续谱**：从轻度（变量改名）到重度（函数重写）。轻度可降到 Cat I，重度必须 Cat II。论文里要明确报每段的占比。
3. **跨 repo / vendored 库**：trace 历史在 vendor/import commit 截断。**论文 scope out**。
4. **Compile-time #ifdef**：V 含代码但被 build flag 禁用。属于 Cat III 的边界。**论文可 scope out**。
5. **运行时 reachability**：V 含代码但实际不可达。属于 Cat III 的极端形式。**论文可 scope out**。
6. **A1.b**：V 含等价保护以不同形式存在。Cat III 的边缘 case，实际罕见但要承认存在。
