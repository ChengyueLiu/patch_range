# Related Work — Reference List

整理这个领域的相关工作，分门别类。已下载用 `[x]` 标，未下载用 `[ ]` 标。

---

## Study 本身（基准、评估对象的来源）

- [x] **[Study]** Chen, Liu, Cao, Xiao, et al. *Vulnerability-Affected Versions Identification: How Far Are We?* arXiv:2509.03876v2, 2025-09-09. → `study.pdf`

---

## Tracing 类工具（基于 SZZ 的回溯方法）

Study 评估的 6 个 tracing tools，均已下载到 `tools/trace/`：

- [x] **[17] VCCFinder** — Perl et al. *VCCFinder: Finding Potential Vulnerabilities in Open-Source Projects to Assist Code Audits.* CCS 2015.
- [x] **[18] Vulnerability Lifetimes** — Alexopoulos et al. *How Long Do Vulnerabilities Live in the Code? A Large-Scale Empirical Measurement Study on FOSS Vulnerability Lifetimes.* USENIX Security 2022.
- [x] **[19] V-SZZ** — Bao, Xia, Hassan, Yang. *V-SZZ: Automatic Identification of Version Ranges Affected by CVE Vulnerabilities.* ICSE 2022.
- [x] **[20] Sem-SZZ (候选)** — Tang, Ni, Huang, Bao. *Enhancing Bug-Inducing Commit Identification: A Fine-Grained Semantic Analysis Approach.* IEEE TSE 2024.
- [x] **[21] LLM-Enhanced Static Analysis** — Cheng et al. *LLM-Enhanced Static Analysis for Precise Identification of Vulnerable OSS Versions.* arXiv:2408.07321, 2024.
- [x] **[22] LLM4SZZ** — Tang, Liu, Liu, Yang, Bao. *LLM4SZZ: Enhancing SZZ Algorithm with Context-Enhanced Assessment on Large Language Models.* arXiv:2504.01404, 2025.

---

## Matching 类工具（基于 patch 特征匹配）

Study 评估的 matching tools，均已下载到 `tools/match/`：

- [x] **[13] Vision** — Wu et al. *Vision: Identifying Affected Library Versions for Open Source Software Vulnerabilities.* ASE 2024.
- [x] **[24] Verjava** — Sun et al. *Verjava: Vulnerable Version Identification for Java OSS with a Two-Stage Analysis.* ICSME 2022.
- [x] **[25] (Web Vuln Affected Version)** — Shi, Zhang, Luo, Mao, Yang. *Precise (Un)affected Version Analysis for Web Vulnerabilities.* ASE 2022.
- [x] **[26] MOVERY** — Woo, Hong, Choi, Lee. *MOVERY: A Precise Approach for Modified Vulnerable Code Clone Discovery from Modified Open-Source Software Components.* USENIX Security 2022.
- [x] **[27] V1SCAN** — Woo, Choi, Lee, Oh. *V1SCAN: Discovering 1-day Vulnerabilities in Reused C/C++ Open-source Software Components Using Code Classification Techniques.* USENIX Security 2023.
- [x] **[28] MVP** — Xiao et al. *MVP: Detecting Vulnerabilities Using Patch-Enhanced Vulnerability Signatures.* USENIX Security 2020.
- [x] **[29] VUDDY** — Kim, Woo, Lee, Oh. *VUDDY: A Scalable Approach for Vulnerable Code Clone Discovery.* IEEE S&P 2017.

---

## SZZ 算法演化（Tracing 系的理论背景）

写论文的 background / related work 章节会用到。原始 SZZ 必读，其他选读：

- [ ] **[23] 原始 SZZ** — Śliwerski, Zimmermann, Zeller. *When Do Changes Induce Fixes?* ACM SIGSOFT Software Engineering Notes, 2005. ⭐ 必读
- [ ] **[33]** Kim, Zimmermann, Pan, Whitehead. *Automatic Identification of Bug-Introducing Changes.* ASE 2006.
- [ ] **[34]** Da Costa, McIntosh, Shang, Kulesza, Roche, Hassan. *A Framework for Evaluating the Results of the SZZ Approach for Identifying Bug-Introducing Changes.* IEEE TSE 2017.
- [ ] **[35]** Neto, Da Costa, Kulesza. *The Impact of Refactoring Changes on the SZZ Algorithm: An Empirical Study.* SANER 2018.
- [ ] **[30]** Wen, Wu, Liu, Tian, Xie, Cheung, Su. *Exploring and Exploiting the Correlations Between Bug-Inducing and Bug-Fixing Commits.* ESEC/FSE 2019.
- [ ] **[50]** Pellegrini, Lenarduzzi, Taibi. *OpenSZZ: A Free, Open-Source, Web-Accessible Implementation of the SZZ Algorithm.* ICPC 2019.
- [ ] **[31]** Rosa et al. *Evaluating SZZ Implementations Through a Developer-Informed Oracle.* ICSE 2021.
- [ ] **[49]** Rezk, Kamei, McIntosh. *The Ghost Commit Problem When Identifying Fix-Inducing Changes: An Empirical Study of Apache Projects.* IEEE TSE 2022.
- [ ] **[36]** Bludau, Pretschner. *Pr-SZZ: How Pull Requests Can Support the Tracing of Defects in Software Repositories.* SANER 2022.
- [ ] **[32]** Yu, Kang, Widyasari, Lawall, Lo. *Evaluating SZZ Implementations: An Empirical Study on the Linux Kernel.* IEEE TSE 2023.
- [ ] **[37] Neural SZZ** — Tang, Bao, Xia, Huang. *Neural SZZ Algorithm.* ASE 2023.

---

## Patch-based 漏洞代码克隆检测（Matching 系背景与扩展）

跟我们的 4 类特征中"存在/位置"维度直接相关：

- [ ] **[38] ReDeBug** — Jang, Agrawal, Brumley. *ReDeBug: Finding Unpatched Code Clones in Entire OS Distributions.* IEEE S&P 2012. ⭐ matching 系的奠基工作
- [ ] **[39]** Li, Kwon, Kwon, Lee. *A Scalable Approach for Vulnerability Discovery Based on Security Patches.* ATIS 2014.
- [ ] **[40] Patchgen** — Luo, Ni, Han, Yang, Wu, Wu. *Patchgen: Towards Automated Patch Detection and Generation for 1-Day Vulnerabilities.* CCS 2015.
- [ ] **[41] Tracer** — Kang, Son, Heo. *Tracer: Signature-Based Static Analysis for Detecting Recurring Vulnerabilities.* CCS 2022.
- [ ] **[46] HiddenCPG** — Wi, Woo, Whang, Son. *HiddenCPG: Large-Scale Vulnerable Clone Detection Using Subgraph Isomorphism of Code Property Graphs.* WWW 2022.
- [ ] **[42] FIRE** — Feng, Wu, Xue, Pan, Zou, Liu, Jin. *FIRE: Combining Multi-Stage Filtering with Taint Analysis for Scalable Recurring Vulnerability Detection.* USENIX Security 2024. ⭐ 多阶段过滤思路相近
- [ ] **[44] Vmud** — Huang, Lu, Cao, Chen, Peng. *Vmud: Detecting Recurring Vulnerabilities with Multiple Fixing Functions via Function Selection and Semantic Equivalent Statement Matching.* CCS 2024.
- [ ] **[45] Paten** — Lin, Ye, Wang, Wu. *Paten: Identifying Unpatched Third-Party APIs via Fine-Grained Patch-Enhanced AST-Level Signature.* IEEE TSE 2025.
- [ ] **[43]** Xu et al. *Enhancing Security in Third-Party Library Reuse — Comprehensive Detection of 1-day Vulnerability Through Code Patch Analysis.* NDSS 2025.

---

## Affected Version 识别（与我们任务最直接相关，必读）

不是纯 matching 也不是纯 tracing，专门做 affected version：

- [ ] **[52]** He, Wang, Zhu, Wang, Zhang, Li, Yu. *Automatically Identifying CVE Affected Versions with Patches and Developer Logs.* IEEE TDSC 2024. ⭐⭐ 题目最像，必读
- [ ] **[2]** Duan, Bijlani, Xu, Kim, Lee. *Identifying Open-Source License Violation and 1-Day Security Risk at Large Scale.* CCS 2017.
- [ ] **[3] Libdiff** — Dong, Li, Yang, Xiao, Wang, Li, Sun. *Libdiff: Library Version Difference Guided OSS Version Identification in Binaries.* ICSE 2024.
- [ ] **[47]** Dai, Zhang, Xu, Lyu, Wu, Xing, Yang. *Facilitating Vulnerability Assessment Through POC Migration.* CCS 2021.
- [ ] **[48] SymBisect** — Zhang, Hao, Chen, Zou, Li, Li, Zhai, Qian, Lau. *SymBisect: Accurate Bisection for Fuzzer-Exposed Vulnerabilities.* USENIX Security 2024.

---

## 上游漏洞 / 供应链分析（背景，扫一眼就行）

写 motivation 章节用得上：

- [ ] **[4]** Zhao et al. *One Bad Apple Spoils the Barrel: Understanding the Security Risks Introduced by Third-Party Components in IoT Firmware.* IEEE TDSC 2022.
- [ ] **[5]** Zhao et al. *A Large-Scale Empirical Analysis of the Vulnerabilities Introduced by Third-Party Components in IoT Firmware.* ISSTA 2022.
- [ ] **[6]** Yang, Xiao, Xu, Sun, Ji, Zhang. *Enhancing OSS Patch Backporting with Semantics.* CCS 2023.
- [ ] **[7]** Sharifdeen et al. *Automated Patch Backporting in Linux (Experience Paper).* ISSTA 2021.
- [ ] **[8]** Liu, Chen, Fan, Chen, Liu, Peng. *Demystifying the Vulnerability Propagation and its Evolution via Dependency Trees in the npm Ecosystem.* ICSE 2022.
- [ ] **[9]** Zhang, Liu, Chen, Xu, Liu, Fan, Zhang, Liu. *Mitigating Persistence of Open-Source Vulnerabilities in Maven Ecosystem.* ASE 2023.
- [ ] **[10]** Wu, Wen, Wen, Li, Zou, Jin. *Understanding the Threats of Upstream Vulnerabilities to Downstream Projects in the Ecosystem.* ICSE 2023.

---

## NVD / 数据质量相关（写 motivation 用）

- [ ] **[11]** Dong, Guo, Chen, Xing, Zhang, Wang. *Towards the Detection of Inconsistencies in Public Security Vulnerability Reports.* USENIX Security 2019.
- [ ] **[12]** Anwar, Abusnaina, Chen, Li, Mohaisen. *Cleaning the NVD: Comprehensive Quality Assessment, Improvements, and Analyses.* IEEE TDSC 2022.
- [ ] **[14]** Zhou, Pacheco, Chen, Hu, Xia, Lo, Hassan. *Colefunda: Explainable Silent Vulnerability Fix Identification.* ICSE 2023.
- [ ] **[15]** Zhou, Pacheco, Wan, Xia, Lo, Yang, Hassan. *Finding a Needle in a Haystack: Automated Mining of Silent Vulnerability Fixes.* ASE 2021.
- [ ] **[16]** Luo, Meng, Wang. *Strengthening Supply Chain Security with Fine-Grained Safe Patch Identification.* ICSE 2024.

---

## Study cutoff 后的工作（待搜）

Study 是 2025-09 上传 arXiv 的，更新工作要自己搜：

- 在 [arxiv.org](https://arxiv.org/list/cs.SE/recent) cs.SE / cs.CR 板块搜：`vulnerability affected version identification` / `patch presence detection` / `1-day vulnerability detection`
- Google Scholar 上 study 的 **"Cited by"** 列表，按时间倒序
- 重点关注：ICSE 2026 / FSE 2026 / USENIX Security 2026 / NDSS 2026 / S&P 2026 的预印本

---

## 阅读优先级建议（如果时间紧）

**第一批 — 必读（理解 baseline 和题目）**
[19] V-SZZ、[26] MOVERY、[27] V1SCAN、[29] VUDDY、[42] FIRE、[52] He et al.、[23] 原始 SZZ

**第二批 — 理解传统**
[17] VCCFinder、[28] MVP、[38] ReDeBug、[34] SZZ Framework、[37] Neural SZZ

**第三批 — 跟踪新方法**
[21] LLM-Enhanced、[22] LLM4SZZ、[44] Vmud、[45] Paten、[43] 1-day NDSS 2025

---

## 用法说明

- 每读完一篇，把 `[ ]` 改成 `[x]` 并在条目下加一两句"它怎么做的、用了 4 类特征里的哪几个"
- 这份文档是给我们写 Related Work 章节 + 4 维度对照表的素材库
