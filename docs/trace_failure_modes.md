# Trace 流派的 4 步流程 + 每步的失败模式

现有 trace 系工具（V-SZZ / SEM-SZZ / LLM4SZZ 等）大体都按这 4 步走。
每一步都可能在不同地方断，并对应不同的 A 类困难。

---

## 4 步流程

```
fix commit
   │
   ▼
①  挑 vuln 代码          （在 fix 里挑哪几行是漏洞）
   │
   ▼
②  反向追溯              （找哪个 commit 引入了这几行）
   │
   ▼
③  从候选挑真 intro       （追溯可能给一堆候选，挑对的）
   │
   ▼
④  intro + fix → tag     （算 affected tags）
   │
   ▼
affected versions
```

---

## 4 步 × 失败模式总览

| 步骤 | 主流办法 | 主要失败模式 | 对应 A 类 |
|---|---|---|---|
| ① 挑 vuln 代码 | 拿 deleted lines | fix 没删任何行 / 删的是 cosmetic | **A1** |
| ② 反向追溯 | git blame | 文件改名 / 代码跨文件搬 / 代码被重写 | **A2, A3** |
| ③ 挑真 intro | 拿最早的候选 | file 比 vuln 代码早（feature 后加进文件） | （结构性 FP，不在 A 编号里） |
| ④ 推 tag | tag --contains | cherry-pick fix / 多分支独立 intro / partial fix | **A4, A5, A6** |

→ **A1-A7 在这 4 步上分布均匀**，没有某一步独大。  
→ 设计新方法时每一步都要单独考虑改进，不能只攻一处。
