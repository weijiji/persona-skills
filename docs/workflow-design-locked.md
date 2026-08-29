# Code Review Workflow — 设计定稿

> 状态：**已锁定**（2026-08-30，经 `grill-with-docs` 逐轮收口）。
> 上游建议稿：[code-review-workflow-design.md](./code-review-workflow-design.md)。
> 相关：ADR 0001~0004；领域术语见 [CONTEXT.md](../CONTEXT.md)。

## 1. 目标

在比赛限定的代码变更范围内，用最少的 LLM token 获得最高的漏洞检出率。以 **OWASP Top 10:2025** 的 A01~A10 分类与 CWE 映射作为唯一分类基线。

**指标优先级**：`Recall > FPR > Token Cost`；Token Cost 是硬预算，FPR 是软目标（≤10%）。

## 2. 已锁定决策（决策树收口）

| # | 决策 | 值 |
| --- | --- | --- |
| R1 | 竞赛输入与评分 | 限定 git diff 范围；Recall 优先；token 有限 |
| R2 | 分类基线 | OWASP 2025 A01~A10 官方 CWE 映射，不自定义 |
| R3 | 技术栈 | Git + Shell + Python(编排) + JSON(Agent 通信) + grep/ripgrep + 轻量 AST + LLM；Semgrep 可选增强层 |
| R4 | 开发顺序 | 测试先行：先 Test Corpus 后 Rule（ADR-0001） |
| 1 | 指标排序 | Recall > FPR > Token Cost；FPR 软上限 10%，Token 硬预算 |
| 2 | 首轮覆盖 | A01~A05 五类，每类 3~5 模式，共 19 条（见 §5） |
| 3 | 角色 | 3 认知角色：Change Analyzer / Security Reviewer / Verifier（ADR-0002） |
| 4 | Test Corpus | 每类 3~5 positive + 2~3 negative；语言锁 Python（A03 用 manifest 样例） |
| 5 | Context Budget | `{max_diff_lines:3000, max_context_files:10, max_review_tokens:12000, max_verification_tokens:5000}` |
| 6 | Git 输入 | 默认 `git diff`（working tree vs HEAD，staged+unstaged 并集）；可选 `--cached` / `BASE..HEAD` |
| 7 | 大 diff | 永不静默截断；四档（全量 / 信号锚定窗口 / 拒绝超限 / 显式记录） |
| 8 | LLM 黑名单 | 密钥原文 / 生成代码 / 二进制 / 无关文件四类禁入 |
| 9 | 路由 | 三层规则路由：静态结案(0 token) / 语义进 Reviewer / 低置信跳过；路由非 LLM |
| 10 | Verifier | 对抗式复核 + 三态 Verdict（CONFIRMED / REJECT / ESCALATE） |
| 11 | 数据契约 | change.json / Impact Map / candidate.json / finding.json / annotation.json（见 §4） |
| 12 | Signal | 两遍扫描：Pass1 grep 全量 → Pass2 AST 句法邻接；不做完整数据流（ADR-0004） |
| 13 | 报告 | JSON + Markdown 摘要 + 被拒候选附录（比赛未指定格式） |

## 3. 管线总览

```text
/code-review
      ↓
① Git Collector      git diff/--cached/status → change.json
      ↓
② Change Analyzer    (静态) → Impact Map：tech_stack / risk_class / relevant_rules
      ↓
③ Signal Engine      Pass1 grep → Pass2 AST 邻接 → candidate.json（LLM 只见证据窗口）
      ↓
④ Risk Router        静态结案 | 进 Reviewer | 跳过
      ↓
⑤ Security Reviewer  candidate + 规则口径 → finding.json（CWE/严重度/证据）
      ↓
⑥ Verifier           对抗式三态 Verdict（仅 ESCALATE 追加 token）
      ↓
⑦ Dedup/Merge        key=(file, line_span, cwe)
      ↓
⑧ 报告               JSON + Markdown
```

核心原则（ADR-0003）：**LLM 永远不看完整 diff，只看 Signal 锚定的证据窗口**。因此 Signal 质量是 Recall 的天花板，扩 Rule 优先于调 Prompt。

## 4. 数据契约

- **change.json**（Git Collector → Analyzer）：`meta{base,head,total_added,total_deleted}` + `changes[]`，每项 `{file, lang, status(added/modified/deleted/renamed), size_lines, hunks[]}`，hunk 含 `{new_start, new_lines, old_start, old_lines, code}`。
- **Impact Map**（Analyzer → Signal Engine，纯静态）：按文件 `{tech_stack, framework, risk_class, changed_functions, relevant_rules[]}`。
- **candidate.json**（Signal Engine → Reviewer）：`{candidate_id, category, pattern, file, line, evidence[], context}`；evidence 形如 `{kind: endpoint|user_controlled|sink, value}`。
- **finding.json**（Reviewer/Verifier 输出）：`{finding_id, candidate_id, category, cwe, severity, verdict, confidence, location, evidence[], fix_hint}`。
- **annotation.json**（Ground Truth，Test Corpus）：`{sample_id, category, cwe, vulnerable, pattern, lines[], note}`。

## 5. 规则基线（M4 首批 19 条）

| 类别 | 关键 CWE | 规则 |
| --- | --- | --- |
| A01 Broken Access Control | 200, 918(SSRF), 352(CSRF) | `idor_missing_scope_check` / `handler_without_auth` / `ssrf_user_url` / `csrf_state_change` |
| A02 Security Misconfiguration | 16, 611(XXE) | `debug_enabled` / `default_credentials` / `permissive_cors` / `xxe_parser` |
| A03 Software Supply Chain Failures | 477, 1104, 1329, 1395 | `unpinned_dependency` / `missing_lockfile` / `untrusted_registry` |
| A04 Cryptographic Failures | 327, 331, 338 | `hardcoded_secret` / `weak_crypto` / `weak_rng` |
| A05 Injection | 89, 79, 78, 94/95 | `sql_concat` / `command_concat` / `eval_injection` / `xss_innerHTML` |

## 6. 里程碑 M1~M9

| 阶段 | 完成什么 | 目标 |
| --- | --- | --- |
| M1 | Skill + 项目骨架 + 首批 Test Corpus | 能启动、能度量 |
| M2 | Git Collector | 准确拿 Change Set |
| M3 | Change Analyzer | Impact Map |
| M4 | Signal Engine | 低成本产 Candidate |
| M5 | Risk Router | 决定审什么 |
| M6 | Security Reviewer | 判断真实漏洞 |
| M7 | Verifier + Dedup | 压 FPR |
| M8 | A01~A10 扩展 | 冲 60 分 |
| M9 | Extra + Token 优化 | 冲榜 |

**当前位置**：M3 Change Analyzer 施工中（M1 骨架+靶场、M2 Git Collector 已完成验收；M2 交付见 [SKILL.md](../code-review/SKILL.md)）。

## 7. 第一版明确不做

10 个 Subagent / 复杂 Swarm / 248 CWE 全量规则 / 自动修复 / 漂亮 UI / MCP / RAG / 向量库 / 完整数据流 AST / 自动 PoC。
