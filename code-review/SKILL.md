---
name: code-review
description: 对一次 git 代码变更做 OWASP Top 10:2025 安全审查，产出结构化 Finding 与报告。目标是限定变更范围内用最少 LLM token 获得最高检出率。
---

# /code-review — OWASP 2025 安全审查

> **M3 施工中**：M1（骨架 + 靶场）与 M2（Git Collector）已完成并验收。本项目按 [设计定稿](../docs/workflow-design-locked.md) 逐里程碑建设（M1 骨架 → M2 Git Collector → … → M9）。本文件是 Skill 入口，管线各阶段在 workflow/ 中落地。

## 使用方式（M2 起生效）

```bash
/code-review                     # 审查 working tree vs HEAD（staged+unstaged 并集）
/code-review --cached            # 仅审查已 staged 变更
/code-review BASE..HEAD          # 审查指定 commit 范围
```

## M2 已落地：Git Collector

`code-review/workflow/collect.py` —— 把一次 git 变更收成 `change.json`（零第三方依赖）。

```bash
python workflow/collect.py [-o change.json]            # 默认：working tree vs HEAD（staged+unstaged 并集）
python workflow/collect.py --cached                    # 仅已 staged
python workflow/collect.py BASE..HEAD                  # 指定 commit 范围
```

- 永不静默截断；二进制只记 `binary:true`；默认模式额外收录 untracked 文本文件（`--no-untracked` 关闭）。
- 验收：`tests/m2/run_tests.py`（34 断言）+ `tests/m2/bridge_corpus.py`（全量靶场 50 断言）。

## 管线（当前为蓝图）

```text
① Git Collector → ② Change Analyzer → ③ Signal Engine → ④ Risk Router
→ ⑤ Security Reviewer → ⑥ Verifier → ⑦ Dedup/Merge → ⑧ 报告
```

核心约定（设计定稿 §3）：

- **LLM 只看 Signal 锚定的证据窗口，不读完整 diff**（ADR-0003）。
- 路由 / 技术栈识别是规则与静态判断，不消耗 LLM token。
- Context Budget 是硬约束：`max_diff_lines 3000 / max_context_files 10 / max_review_tokens 12000 / max_verification_tokens 5000`。
- 密钥原文等四类内容永不进入 LLM。

## 分类基线

OWASP Top 10:2025 官方 A01~A10（248 CWE）。首批规则见 `rules/A01..A05`（19 条，M4 落地）。

## 进度

- [x] 设计收口（ADR 0001~0004，[设计定稿](../docs/workflow-design-locked.md)）
- [x] M1 骨架 + Test Corpus 结构
- [x] M1 Test Corpus 样本生成（A01~A05，15 positive + 10 negative + annotation.json）
- [x] M2 Git Collector（`workflow/collect.py`，验收 34 + 50 断言通过）
- [ ] M3 Change Analyzer
- [ ] M4 Signal Engine + 规则
- [ ] M5 Risk Router
- [ ] M6 Security Reviewer
- [ ] M7 Verifier + Dedup
- [ ] M8 A01~A10 扩展
- [ ] M9 Extra + Token 优化
