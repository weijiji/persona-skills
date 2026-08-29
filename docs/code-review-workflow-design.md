我建议我们采用一种“陪跑式”方式：**我一次带你完成一个阶段，阶段完成后再进入下一阶段**。这样你最终得到的不是一堆 Prompt，而是一个可以参赛的 `/code-review` Skill。

先校准一个关键点：你题目中的 A01~A10 与 **OWASP Top 10:2025** 完全对应。2025 版一共有 248 个 CWE 分布在十个类别中，而且 OWASP 自己明确指出，Top 10 更适合作为最低安全基线，不能声称仅靠工具就能“全面检测” Top 10，尤其 A06 Insecure Design 本身就存在很强的语义/设计判断属性。([OWASP Foundation][1])

所以我们的目标不是：

> “做一个万能漏洞扫描器。”

而是：

> **在比赛限定的代码变更范围内，用最少的 LLM token 获得最高的漏洞检出率。**

---

# 总体施工图

我们最后要造出：

```text
/code-review
      │
      ▼
┌──────────────────────┐
│ 1. Git Change Collector│
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 2. Change Analyzer   │
│    文件/函数/技术栈分析 │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 3. Security Signal   │
│    Engine            │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 4. Risk Router       │
└──────────┬───────────┘
           ▼
     ┌─────┴─────┐
     ▼           ▼
  Static       LLM Review
  Evidence
     │           │
     └─────┬─────┘
           ▼
┌──────────────────────┐
│ 5. Finding Verifier  │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 6. Dedup / Merge      │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 7. Extra Vulnerability│
│    Discovery          │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ 8. Final Report       │
└──────────────────────┘
```

但**我们不会一次写完这 8 个模块**。

---

# 第一阶段：先建立比赛的“地基”

今天第一步，我甚至不让你写 Agent。

我们先建立：

```text
/code-review
```

的工程目录和测试靶场。

原因很简单：

**没有测试样本，你根本无法知道自己的 Workflow 是真的有效，还是 Prompt 看起来很厉害。**

---

# Step 1：确定技术路线

我建议第一版使用：

| 东西           | 用途                  |
| ------------ | ------------------- |
| Git          | 获取待审查变更             |
| Shell        | 基础扫描、文件操作           |
| Python       | 编排、解析、规则执行          |
| JSON         | Agent 间结构化通信        |
| LLM          | 语义代码审查              |
| AST          | 代码结构分析              |
| grep/ripgrep | 低成本候选发现             |
| Semgrep（可选）  | SAST / data-flow 辅助 |
| Skill        | 最终用户入口              |

Semgrep 之类的工具可以作为增强层，但**不要一开始就把整个方案绑定到某个 SAST 工具**。

原因是比赛真正需要的是：

```text
Workflow
    >
Tool
```

而不是：

```text
Semgrep
    =
你的方案
```

---

# Step 2：先建立项目

我建议目录直接这样：

```text
code-review/
│
├── SKILL.md
│
├── workflow/
│   ├── 01_collect.md
│   ├── 02_analyze.md
│   ├── 03_signal_scan.md
│   ├── 04_route.md
│   ├── 05_review.md
│   ├── 06_verify.md
│   ├── 07_merge.md
│   ├── 08_extra.md
│   └── 09_report.md
│
├── rules/
│   ├── A01/
│   ├── A02/
│   ├── A03/
│   ├── A04/
│   ├── A05/
│   ├── A06/
│   ├── A07/
│   ├── A08/
│   ├── A09/
│   ├── A10/
│   └── EXTRA/
│
├── schemas/
│   ├── change.json
│   ├── candidate.json
│   ├── finding.json
│   └── review.json
│
├── scanners/
│   ├── git/
│   ├── pattern/
│   └── ast/
│
├── prompts/
│   ├── analyzer.md
│   ├── reviewer.md
│   ├── verifier.md
│   └── extra.md
│
└── tests/
    ├── A01/
    ├── A02/
    ├── A03/
    ├── A04/
    ├── A05/
    ├── A06/
    ├── A07/
    ├── A08/
    ├── A09/
    ├── A10/
    └── EXTRA/
```

**先不要填内容。**

先把骨架建立起来。

---

# Step 3：我们第一批真正要做的不是 10 个 Rule，而是 Test Corpus

这是整个项目最容易被忽视、但我认为最重要的东西。

例如：

```text
tests/A01/
```

至少建立：

```text
positive/
negative/
```

于是：

```text
tests/A01/positive/
    idor.py
    missing_authorization.py
    privilege_escalation.py

tests/A01/negative/
    authorized_resource.py
    role_checked.py
```

A05：

```text
tests/A05/positive/
    sql_injection.py
    command_injection.py
    xss.py

tests/A05/negative/
    parameterized_sql.py
    escaped_output.py
```

……

最终：

```text
tests/
├── A01/
│   ├── positive/
│   └── negative/
├── A02/
│   ├── positive/
│   └── negative/
...
└── A10/
    ├── positive/
    └── negative/
```

---

# 为什么我强烈要求先做这个？

因为比赛的真实目标不是：

> “让 AI 输出一份很专业的 Security Report。”

而是：

```text
                  Ground Truth
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
      漏洞存在                    漏洞不存在
          │                         │
          ▼                         ▼
       AI发现？                    AI误报？
```

你最终真正要优化的是：

$$
Recall=\frac{TP}{TP+FN}
$$

以及：

$$
FalsePositiveRate=\frac{FP}{FP+TN}
$$

再加上：

$$
TokenCost
$$

所以我们最后应该能得到一个类似这样的比赛仪表盘：

```text
A01     9/10 detected
A02     8/10 detected
A03     10/10 detected
...
A10     7/10 detected

Recall:       87.2%
False Positive: 6.4%
LLM Calls:     14
Tokens:        38,421
```

这才是真正可以迭代的工程。

---

# Step 4：第一版不要追求 248 个 CWE

这里我特别提醒你。

OWASP 2025 确实包含 **248 个 CWE**，例如 A01 就包含 40 个 CWE。([OWASP Foundation][2])

但是：

**现在千万不要做 248 个规则。**

我们的第一版目标是：

```text
A01 → 3~5 个高价值模式
A02 → 3~5 个
...
A10 → 3~5 个
```

即：

> **先覆盖 30~50 个高概率漏洞模式。**

比赛第一轮跑起来以后，再根据测试结果扩充。

---

# Step 5：我们第一批 Rule 只做 5 个

为了验证整个架构，我建议第一轮甚至只实现：

### A01

```text
IDOR / BOLA
```

### A02

```text
危险配置 / Debug / 默认凭据
```

### A03

```text
危险依赖 / CI/CD 不安全
```

### A04

```text
弱加密 / 硬编码密钥
```

### A05

```text
SQL Injection
```

为什么不是先做十个？

因为我们现在要验证：

```text
Git
 ↓
Signal
 ↓
Router
 ↓
LLM
 ↓
Finding
 ↓
Verification
```

**整个流水线能不能跑通。**

---

# Step 6：第一版的 Agent 数量

这里我们也先锁死。

## Agent ①：Change Analyzer

负责：

> “这次 commit 改了什么？”

不是找漏洞。

---

## Agent ②：Security Reviewer

负责：

> “根据已经发现的 Signal，判断是否真的存在漏洞。”

---

## Agent ③：Verifier

负责：

> “这个 Finding 是真的吗？”

---

### 暂时没有：

```text
A01 Agent
A02 Agent
A03 Agent
...
A10 Agent
```

也没有：

```text
10 Subagents
```

第一版：

```text
3 个认知角色
```

---

# Step 7：第一条真正的 Workflow

我们先把最小闭环做出来：

```text
/code-review
      ↓
git diff
      ↓
Change Analyzer
      ↓
Security Signal Scanner
      ↓
Security Reviewer
      ↓
Verifier
      ↓
Report
```

例如用户提交：

```python
@app.get("/users/{id}")
def get_user(id):
    return db.get_user(id)
```

程序首先发现：

```text
SIGNAL:
endpoint + user-controlled identifier + database lookup
```

然后才给 AI：

```text
Review this candidate for A01.

Evidence:
- endpoint: GET /users/{id}
- identifier: id
- sink: db.get_user(id)

Determine whether authorization / ownership
verification exists.
```

AI：

```text
CONFIRMED
A01
CWE-639
HIGH
```

Verifier：

```text
CONFIRMED
confidence = 0.94
```

最终报告。

---

# Step 8：最重要的一个设计——Context Budget

从第一天就建立：

```text
context_budget
```

例如：

```json
{
  "max_diff_lines": 3000,
  "max_context_files": 10,
  "max_review_tokens": 12000,
  "max_verification_tokens": 5000
}
```

然后所有 Agent 都遵守：

> **不能无限读取 repository。**

如果发现：

```text
user_api.py
```

需要了解：

```text
auth middleware
```

才允许额外读取：

```text
auth/middleware.py
```

而不是：

```text
整个 repository
```

这就是我们的 Token Optimization 核心。

---

# Step 9：第一阶段暂时不要做的东西

你可能很容易陷入这些：

```text
❌ 10 个 Subagent
❌ 复杂 Agent Swarm
❌ 248 CWE
❌ 自动修复代码
❌ 漂亮 UI
❌ MCP
❌ RAG
❌ 向量数据库
❌ 超复杂 AST
❌ 自动生成 PoC
```

全部先不做。

第一阶段只完成：

```text
Git Diff
   ↓
5类 Signal
   ↓
1个 Reviewer
   ↓
1个 Verifier
   ↓
结构化 Finding
```

---

# 我们接下来就按这个顺序施工

我建议把整个项目拆成 **9 个里程碑**：

| 阶段     | 我们要完成什么                    | 目标         |
| ------ | -------------------------- | ---------- |
| **M1** | 建立 Skill + 项目骨架            | 能启动        |
| **M2** | Git Collector              | 能准确拿到待提交内容 |
| **M3** | Change Analyzer            | 能判断修改影响    |
| **M4** | Security Signal Engine     | 能低成本找候选    |
| **M5** | Risk Router                | 能决定该审什么    |
| **M6** | Security Reviewer          | 能判断真实漏洞    |
| **M7** | Verifier + Dedup           | 降低误报       |
| **M8** | A01~A10 扩展                 | 冲 60 分     |
| **M9** | Extra + Token Optimization | 冲榜         |

**我们现在只做 M1。**

---

## M1：你现在需要做的事情

如果你准备正式开始，我建议你先创建一个空的：

```text
code-review/
```

然后把上面的目录建出来。

**暂时不要写任何 Prompt。**

然后我们下一步直接做：

> **M2：Git Collector**

我会具体带你设计它，包括：

* 到底执行哪些 `git` 命令
* `git diff`、`git diff --cached`、`git status` 怎么组合
* 怎样判断用户说的“待提交”究竟是 staged 还是 working tree
* 如何处理“修改量非常大”的情况
* 如何把 diff 转成结构化 JSON
* 哪些内容绝对不能直接送进 LLM
* 如何为后面的 Router 准备输入
* 最后给你**可以直接放进 Skill 的 workflow 文件内容**

这样我们就不是“讨论一个方案”，而是**一层一层把 `/code-review` 真的搭出来**。

还有一点很关键：我会把 **OWASP Top 10:2025 的官方分类作为我们的基线，而不是凭印象自己编 A01~A10 规则**；尤其 A03、A09、A10 都是 2025 版的重要变化，A10 还是新类别。([OWASP Foundation][2])

[1]: https://owasp.org/Top10/?utm_source=chatgpt.com "OWASP Top 10:2025"
[2]: https://owasp.org/Top10/2025/0x00_2025-Introduction/?utm_source=chatgpt.com "Introduction - OWASP Top 10:2025"
