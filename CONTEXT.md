# Code Review Skill（OWASP 2025 安全竞赛）

为安全竞赛构建的 `/code-review` Skill 的领域模型。目标：在比赛限定的代码变更范围内，用最少的 LLM token 获得最高的漏洞检出率。以 **OWASP Top 10:2025** 的 A01~A10 分类与 CWE 映射作为唯一分类基线。

## Language

**Change Set**：
待审查的代码变更单元。由 Git Collector 从 `git diff` / `--cached` / `status` 组合出，转成结构化 JSON。
_Avoid_: commit、diff、repo、raw patch

**Signal**：
Signal Engine 用低成本静态手段（grep/ripgrep/AST）发出的"此处值得进一步确认"的候选提示。是触发 LLM 审查的门票，不是漏洞结论。
_Avoid_: 线索、hint、flag

**Candidate**：
一条带结构化证据的潜在漏洞位置（如 endpoint + 用户可控 identifier + 危险 sink），是送进 LLM 的最小审查单元。
_Avoid_: 可疑点、spot、possible issue

**Finding**：
LLM 审查后确认的漏洞结论，包含 A0x 类别、CWE、严重度、置信度与证据。
_Avoid_: issue、问题、report item

**Rule**：
绑定到某个 CWE 的检测模式。第一版覆盖 30~50 个高概率模式，不追求 OWASP 2025 的全部 248 个 CWE。
_Avoid_: detector、checker

**Risk Router**：
在"静态可判"与"LLM 审查"之间做路由的决策点，受 Context Budget 约束。
_Avoid_: 调度器、dispatcher

**Impact Map**：
Change Analyzer 的产出：按文件给出 技术栈/框架、risk_class、changed_functions、relevant_rules（用于过滤 Signal Engine 要跑的规则列表）。全部静态判定，不消耗 LLM token。Analyzer 产出过滤，不产漏洞。
_Avoid_: 分析报告、file report、影响面

**Verifier**：
对 Finding 做二次确认、输出置信度的角色。作用是压低 False Positive Rate。
_Avoid_: 复核、double-check

**Verdict**：
Verifier 对 Finding 的判定结论，三态：CONFIRMED（进报告）、REJECT（丢弃并记入 FPR 日志）、ESCALATE（证据不足，用额外上下文重审一次，唯一允许追加 token 的分支）。
_Avoid_: 结论、判定结果

**Context Budget**：
硬性的 token / 行数上限集合（max_diff_lines、max_context_files、max_review_tokens、max_verification_tokens）。所有 Agent 必须遵守，禁止无限读取 repository。
_Avoid_: 预算、token limit

**Test Corpus**：
每个 A0x 类别下的 positive / negative 样本集，是 Ground Truth 的来源。在写任何 Rule 之前先建立。
_Avoid_: 测试集、examples

**Ground Truth**：
测试样本中"漏洞是否存在"的确定事实，用于计算 Recall 与 FPR。
_Avoid_: 标注、answer key

**Recall**：
TP / (TP + FN)，检出率。
_Avoid_: 召回率（同义，但术语统一用 Recall）

**False Positive Rate**：
FP / (FP + TN)，误报率。
_Avoid_: 误报率（同义，但术语统一用 FPR）

**Token Cost**：
整个审查流程消耗的 LLM token 总量，是与 Recall / FPR 并列的优化目标。
_Avoid_: 成本、spend

**陪跑式（Mentored Milestones）**：
一次只完成一个阶段的施工方式，阶段完成验收后才进入下一阶段。最终产物不是一批 Prompt，而是一个可参赛的 `/code-review` Skill。
_Avoid_: 一次性写完、waterfall 式交付
