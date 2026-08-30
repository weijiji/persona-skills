---
name: code-review
description: 对一次 git 代码变更做 OWASP Top 10:2025 安全审查，产出结构化 Finding 与报告。目标是限定变更范围内用最少 LLM token 获得最高检出率。
---

# /code-review — OWASP 2025 安全审查

> **M8 施工中**：M1（骨架 + 靶场）、M2（Git Collector）、M3（Change Analyzer）、M4（Signal Engine）、M5（Risk Router）、M6（Security Reviewer）、M7（Verifier + Dedup）已完成并验收。本项目按 [设计定稿](../docs/workflow-design-locked.md) 逐里程碑建设（M1 骨架 → M2 Git Collector → … → M9）。本文件是 Skill 入口，管线各阶段在 workflow/ 中落地。

## 使用方式（M2 起生效）

```bash
/code-review                     # 审查 working tree vs HEAD（staged+unstaged 并集）
/code-review --cached            # 仅审查已 staged 变更
/code-review BASE..HEAD          # 审查指定 commit 范围
```

## 运行时流程（`/code-review` 被调用时按此执行）

1. 确认当前在目标 git 仓库内（`git rev-parse --show-toplevel`）。
2. 记 `SKILL_DIR` = 本文件（SKILL.md）所在目录；以下命令都在目标仓库根目录执行，产物落当前目录。
3. **静态管线 ①~④**（0 LLM token，逐个跑，任一失败即停）：
   ```bash
   python "$SKILL_DIR/workflow/collect.py" -o change.json
   python "$SKILL_DIR/workflow/analyze.py" -i change.json -o impact_map.json
   python "$SKILL_DIR/workflow/signal_engine.py" -c change.json -m impact_map.json -o candidate.json
   python "$SKILL_DIR/workflow/router.py" -c candidate.json -o review_plan.json
   ```
4. **初审 ⑤**（首个 LLM 阶段）：打包 → 你（Claude）判定 → 合并。
   ```bash
   python "$SKILL_DIR/workflow/reviewer.py" build -r review_plan.json -c candidate.json -o review_pack.json
   ```
   读 `review_pack.json`：对每条候选按 `rule_ask` 口径 + `evidence/context` 窗口判
   `confirm/reject`，写 `review_answers.json`（格式见 `schemas/review_answers.json`）。
   ```bash
   python "$SKILL_DIR/workflow/reviewer.py" review -r review_plan.json -c candidate.json \
       --answers review_answers.json -o finding.json
   ```
5. **对抗复核 ⑥**：打包 → 你（Claude）三态判定 → 应用。
   ```bash
   python "$SKILL_DIR/workflow/verifier.py" build -i finding.json -o verification_pack.json
   ```
   读 `verification_pack.json`：对每条 finding 对抗式判 `confirm/reject/escalate`（escalate 项用更宽
   局部窗口重审，仍不读完整 diff），写 `verification_answers.json`。
   ```bash
   python "$SKILL_DIR/workflow/verifier.py" verify -i finding.json --answers verification_answers.json -o finding.json
   ```
6. **去重 ⑦**：
   ```bash
   python "$SKILL_DIR/workflow/verifier.py" dedup -i finding.json -o finding.json
   ```
7. 读终态 `finding.json`，向用户汇报结构化审查结论（findings + rejected 附录）。
   若预算不够，分阶段汇报；被拒候选不隐瞒，列入附录供调优（R13）。
   **⑧ 报告类别编号门禁（重要）**：报告每条漏洞的「OWASP 2025」类别编号必须以
   `rules/registry.json` 为唯一权威（A05 注入 = CWE-89/78/79/94/95，A10 = CWE-601 等），
   **禁止凭 OWASP 记忆编号**（官方把注入编为 A03，项目基线是 A05——两者混用正是历史 bug）。
   报告写完后先运行门禁，全部通过才算定稿：
   ```bash
   python "$SKILL_DIR/workflow/report_check.py" -f SECURITY_REVIEW.md --registry "$SKILL_DIR/rules/registry.json"
   ```
   registry 未覆盖的 CWE（如路径穿越 CWE-22）不得编造 A 编号——表格里注明「官方 OWASP 2025 映射，
   项目规则未覆盖」即可放行。类别编号表（项目分类基线，设计定稿 §5）：
   `A01 访问控制 / A02 安全配置错误 / A03 软件供应链 / A04 加密失败 / A05 注入 /
   A06 过时组件 / A07 认证失败 / A08 完整性失败 / A09 日志监控失败 / A10 SSRF`。

## M2 已落地：Git Collector

`code-review/workflow/collect.py` —— 把一次 git 变更收成 `change.json`（零第三方依赖）。

```bash
python workflow/collect.py [-o change.json]            # 默认：working tree vs HEAD（staged+unstaged 并集）
python workflow/collect.py --cached                    # 仅已 staged
python workflow/collect.py BASE..HEAD                  # 指定 commit 范围
```

- 永不静默截断；二进制只记 `binary:true`；默认模式额外收录 untracked 文本文件（`--no-untracked` 关闭）。
- 验收：`tests/m2/run_tests.py`（34 断言）+ `tests/m2/bridge_corpus.py`（全量靶场 50 断言）。

## M3 已落地：Change Analyzer

`code-review/workflow/analyze.py` —— 静态读 change.json → impact_map.json（纯静态，0 LLM token）。

```bash
python workflow/analyze.py -i change.json -o impact_map.json
```

- 每文件标注：`framework / file_type / risk_class / topics / changed_functions / relevant_rules`。
- `changed_functions`：Python 用 stdlib `ast` 精确 def 边界，只报**真正被增删行触及**的函数（上下文行不算）。
- `relevant_rules`：来自 `rules/registry.json`（27 条规则 × 适用语言）资格粗筛——**只答"该试哪些规则"，不检测**（检测在 M4）。
- 验收：`tests/m3/run_tests.py`（80 断言，含全量 positive 样本规则资格桥接）。

## M4 已落地：Signal Engine

`code-review/workflow/signal_engine.py` —— Pass1 grep + Pass2 AST 邻接 → `candidate.json`（纯静态，0 LLM token）。

```bash
python workflow/signal_engine.py -c change.json -m impact_map.json -o candidate.json
```

- **27 条规则全部有检测器**（A01~A10）：注入类（sql/command/eval/xss）用 AST 判定"参数化/字面量 vs 插值拼接"；A01 越权用函数级邻接（端点内有无鉴权守卫、有无用户输入、资源访问锚点）；配置/供应链类纯行级正则；A06~A10（浮动依赖 / 明文口令比对 / 弱口令策略 / 会话过期 / 不安全反序列化 / 关闭 TLS 校验 / 日志注入 / 堆栈泄露 / 开放重定向）在 M8 补齐。
- 候选只锚定在**本次 diff 新增的行**（改哪看哪）；`confidence`（high/medium/low）喂给 ④ Risk Router。
- **密钥脱敏在证据窗口构建时**：`hardcoded_secret` 的 evidence/context 一律 scrub，密钥原文不落盘、不进 LLM（ADR-0003）。
- 共用工具抽到 `workflow/gitutil.py`（②③ 同源，避免漂移）。
- 验收：`tests/m4/run_tests.py`（182 断言：30 positive 命中 + 20 negative 干净 + 脱敏 + 变更行锚定 + 9 条合成夹具边界 + 契约）。

## M5 已落地：Risk Router

`code-review/workflow/router.py` —— 三层规则路由 → `review_plan.json`（纯规则，0 LLM token）。

```bash
python workflow/router.py -c candidate.json -o review_plan.json
```

- 4 种决策（R9 三层展开）：
  - **finding**（静态结案为漏洞，0 token）：字面量即漏洞的确定性规则——`hardcoded_secret` / `permissive_cors` / `debug_enabled` / `default_credentials` / `unpinned_dependency` / `floating_dependency` / `tls_verify_disabled`（high 命中时直接出 finding，附 `CONFIRMED_BY_RULE` verdict，跳过 Reviewer；`tls_verify_disabled` 的 disable_warnings 分支 medium 仍走 review）。
  - **review**（进 ⑤ Reviewer）：语义类——注入（sql/command/eval/xss）、越权（idor/ssrf）、弱加密/弱随机数。
  - **skip**（低置信跳过）：基于缺位的弱信号——`handler_without_auth` / `csrf_state_change` / `missing_lockfile` / `untrusted_registry` + 一切 low 置信命中。
  - **clean**（静态结案为无害）：evidence 显示已有防护（sanitizer/鉴权）。
- 输出 `review_plan.json`：`decisions[]` + `findings_static[]`（0-token findings）+ `review_ids[]`（M6 只审这批）。
- 验收：`tests/m5/run_tests.py`（86 断言：30 positive 全路由不漏 + 20 negative 不误报 + 决策表 + 计数闭合 + 契约）。

## M6 已落地：Security Reviewer

`code-review/workflow/reviewer.py` —— 第一个 LLM 阶段：候选 + 规则口径 → `finding.json`。

```bash
python workflow/reviewer.py build  -r review_plan.json -c candidate.json -o review_pack.json
python workflow/reviewer.py review -r review_plan.json -c candidate.json \
        --answers review_answers.json -o finding.json     # Claude 判定
python workflow/reviewer.py review -r review_plan.json -c candidate.json \
        --scripted -o finding.json                        # 确定性兜底（测试/干跑）
```

- **只审 `review_ids`**：M4 已脱敏的有界证据窗口（evidence + context），不看完整 diff（ADR-0003）。
- **规则口径**：`rules/registry.json` 每条规则新增 `review.ask/fix`（审什么、怎么修），随证据包进 LLM 提示。
- **Context Budget 硬约束**（R5/R7）：估算提示 token，超 `max_review_tokens=12000` 自动分批，绝不静默截断；单条自身超限的候选显式记录进 `oversized`。
- **结构化判定**：每条 `verdict(confirm/reject)` + `cwe/severity/reason/fix_hint`；`finalize` 校验答案完整性（缺答/重复/未知 id/非法值均报错）后，与 M5 静态结案合并 → `finding.json`；被拒候选进 `rejected` 附录（R13）。
- `--scripted` 是确定性兜底判定（无 LLM），用于测试与干跑；真实运行由 Claude 读 `review_pack.json` 产出 `review_answers.json`。
- 验收：`tests/m6/run_tests.py`（144 断言：30 positive 全有 finding + 20 negative 零误报 + 兜底判定 + 预算分批 + 脱敏贯通 + 契约 + 校验）。

## M7 已落地：Verifier + Dedup

`code-review/workflow/verifier.py` —— 管线⑥⑦：对抗式三态复核 + 去重合并 → finding.json 终态。

```bash
python workflow/verifier.py build  -i finding.json -o verification_pack.json
python workflow/verifier.py verify -i finding.json --answers verification_answers.json -o finding.json   # Claude 判定
python workflow/verifier.py verify -i finding.json --scripted -o finding.json                           # 确定性兜底（测试/干跑）
python workflow/verifier.py dedup  -i finding.json -o finding.json
```

- **⑥ 对抗式三态复核**（R10）：对每条 finding 尝试推翻（假阳性 / 初审遗漏的缓解 / 数据不可达），输出 `CONFIRMED / REJECT / ESCALATE`。`REJECT` 撤销并进 `rejected` 附录；`ESCALATE`（证据不足以定论，需追加深度复核）保留为 finding 并标记——按设计仅 ESCALATE 追加 token，深度复核在真实流程由 Skill 指示 Claude 扩大窗口做。
- **⑦ Dedup**：按 `key=(file, line_span, cwe)` 合并重复漏洞——span 重叠或相邻（≤2 行）即同一漏洞；合并保留更高严重度/置信度、并集证据、span 并集，`dedup_merged` 显式计数。
- **只复核 findings**：M6 的 `rejected` 附录不再复核；LLM 仍只见有界、已脱敏窗口（ADR-0003）。静态 finding 的 `confidence` 由 M5 补上（静态结案门槛即 conf==high），供复核正确区分。
- **Context Budget 硬约束**（R5/R7）：`max_verification_tokens=5000`，超预算自动分批，单条自身超限进 `oversized` 显式记录，绝不静默截断。
- **结构化判定**：每条 `verdict(confirm/reject/escalate)` + `reason`（confirm 可选覆盖 cwe/severity）；`apply_verdicts` 校验答案完整性，`origin_verdict` 保留 M6 来源（CONFIRMED_BY_RULE / CONFIRMED_BY_REVIEWER）。
- `--scripted` 是确定性兜底对抗复核（无 LLM），用于测试与干跑；真实运行由 Claude 读 `verification_pack.json` 产出 `verification_answers.json`。
- 验收：`tests/m7/run_tests.py`（184 断言：30 positive 复核+去重后仍有 finding + 20 negative 零误报 + 三态判定 + 预算分批 + 脱敏贯通 + 契约 + dedup 合并 + 校验 + CLI 接线）。
  - A03/A06 重叠注记：`unpinned_dependency` 与 `floating_dependency` 同为 CWE-1104，浮动版本行两规则都触发，dedup 按 `(file,cwe)` 合并为一条、保留排序靠前的 A03 命名（设计定稿 §5 已注明的历史命名遗留）；A06 floating 精确 pattern 在 M4/M6 验证，M7 按同族+行号验收。

## 管线（M1~M8 已落地；⑧ 报告类别门禁 `report_check.py` 已落地，完整报告生成仍为蓝图）

```text
① Git Collector → ② Change Analyzer → ③ Signal Engine → ④ Risk Router
→ ⑤ Security Reviewer（M6）→ ⑥ Verifier → ⑦ Dedup/Merge → ⑧ 报告
```

核心约定（设计定稿 §3）：

- **LLM 只看 Signal 锚定的证据窗口，不读完整 diff**（ADR-0003）。
- 路由 / 技术栈识别是规则与静态判断，不消耗 LLM token。
- Context Budget 是硬约束：`max_diff_lines 3000 / max_context_files 10 / max_review_tokens 12000 / max_verification_tokens 5000`。
- 密钥原文等四类内容永不进入 LLM。

## 分类基线

OWASP Top 10:2025 官方 A01~A10（248 CWE）。27 条规则见 `rules/registry.json`（M4 落地检测器）。A01~A05 为首批 18 条（覆盖 A01 越权 / A02 错误配置 / A03 供应链 / A04 加密 / A05 注入）；A06~A10 为 M8 扩展 9 条（覆盖 A06 过时组件 / A07 认证失败 / A08 完整性失败 / A09 日志监控失败 / A10 SSRF 开放重定向）。

## 进度

- [x] 设计收口（ADR 0001~0004，[设计定稿](../docs/workflow-design-locked.md)）
- [x] M1 骨架 + Test Corpus 结构
- [x] M1 Test Corpus 样本生成（A01~A05，15 positive + 10 negative + annotation.json）
- [x] M2 Git Collector（`workflow/collect.py`，验收 34 + 100 断言通过）
- [x] M3 Change Analyzer（`workflow/analyze.py` + `rules/registry.json`，验收 80 断言通过）
- [x] M4 Signal Engine（`workflow/signal_engine.py`，27 条规则检测器，验收 182 断言通过）
- [x] M5 Risk Router（`workflow/router.py`，三层路由 + 静态结案，验收 86 断言通过）
- [x] M6 Security Reviewer（`workflow/reviewer.py`，首个 LLM 阶段 + 预算分批 + 合并静态结案，验收 144 断言通过）
- [x] M7 Verifier + Dedup（`workflow/verifier.py`，对抗式三态复核 + 去重合并，验收 184 断言通过）
- [x] M8 A01~A10 扩展（新增 9 规则 + 30 positive/20 negative 靶场，A06~A10 全覆盖，回归 810 断言）
- [x] ⑧ 报告类别编号门禁（`workflow/report_check.py`：CWE→A 编号以 registry.json 为准，禁止凭 OWASP 记忆编号混用官方 A03/基线 A05；回归 `tests/report/run_tests.py` 34 断言）
- [ ] M9 Extra + Token 优化 + 完整 ⑧ Markdown 报告生成
