# /code-review — 安装与使用指南

OWASP Top 10:2025 安全审查 Skill：在**一次 git 代码变更**的范围内，用最少的 LLM token 找出最多的真实漏洞。

```text
① Git Collector → ② Change Analyzer → ③ Signal Engine → ④ Risk Router
→ ⑤ Security Reviewer → ⑥ Verifier → ⑦ Dedup/Merge → ⑧ 报告
```

核心原则：**LLM 永远不看完整 diff**，只看 Signal 锚定的、已脱敏的证据窗口。静态阶段（①②③④）全免费，只有判断"这是不是真漏洞"才花 token。

> **当前状态**：M1~M8 已落地并验收（回归 810/810，A01~A10 全覆盖）。⑧ 报告（人类可读 Markdown）与 M9（Extra + Token 优化）为蓝图。

---

## 前置要求

| 依赖 | 说明 |
| --- | --- |
| git | 目标代码必须在一个 git 仓库里（默认审查 `working tree vs HEAD`） |
| Python 3.x | 无需任何第三方库（全部用标准库） |
| Claude Code | 只有"方式 A"（LLM 判定）需要；"方式 B"纯 CLI 随时可跑 |

---

## 安装

skill 本体就是本仓库的 `code-review/` 目录。装好后 Claude Code 能识别 `/code-review` 这个斜杠命令。

### 方法一：装到单个项目（推荐，比赛用）

把 `code-review/` 目录**整个复制**到目标项目的 `.claude/skills/` 下，目录名必须是 `code-review`：

```bash
# 在目标项目根目录执行
mkdir -p .claude/skills
cp -r /e/Coding/persona-skills/code-review .claude/skills/code-review
```

装完在目标项目里打开 Claude Code，`/code-review` 即可用。

### 方法二：全局安装（所有项目可用）

复制到用户级 skills 目录：

```bash
# Windows 全局
cp -r /e/Coding/persona-skills/code-review "$HOME/.claude/skills/code-review"

# macOS / Linux 全局
cp -r /path/to/persona-skills/code-review "$HOME/.claude/skills/code-review"
```

### 方法三：不安装，直接从源码目录跑（开发中自测）

你在本仓库开发时不需要装，直接在任意目标 git 仓库里指到源码路径跑管线即可（见「方式 B」）。

---

## 使用

### 方式 A：在 Claude Code 里 `/code-review`（自动化，推荐）

在**目标项目的仓库根目录**打开 Claude Code，输入：

```bash
/code-review                     # 审查当前未提交的变更（staged + unstaged 并集）
/code-review --cached            # 只审查已暂存（staged）的变更
/code-review BASE..HEAD          # 审查某段提交范围，如 main..feature
```

Claude 会按 [SKILL.md](code-review/SKILL.md) 里的运行时流程执行：

1. 跑静态管线 ①~④，产出候选；
2. 作为初审员读 `review_pack.json`，按规则口径判定每一条；
3. 作为对抗复核员读 `verification_pack.json`，三态复核每一条；
4. 去重合并，最终汇报 `finding.json` 里的漏洞结论。

### 方式 B：手动跑 CLI 管线（确定性，零 LLM token）

不需要 Claude Code，不需要烧 token——全部走内置的确定性兜底判定（`--scripted`）。适合：干跑验证、CI、快速看结果。

在目标仓库根目录，把 `SKILL` 换成 skill 目录路径，依次执行：

```bash
SKILL=/e/Coding/persona-skills/code-review          # 改成你的 skill 路径

python "$SKILL/workflow/collect.py" -o change.json
python "$SKILL/workflow/analyze.py" -i change.json -o impact_map.json
python "$SKILL/workflow/signal_engine.py" -c change.json -m impact_map.json -o candidate.json
python "$SKILL/workflow/router.py" -c candidate.json -o review_plan.json

# 初审（--scripted = 确定性兜底判定，无 LLM）
python "$SKILL/workflow/reviewer.py" review -r review_plan.json -c candidate.json \
    -o finding.json --scripted
# 对抗复核（三态） + 去重
python "$SKILL/workflow/verifier.py" verify -i finding.json -o finding.json --scripted
python "$SKILL/workflow/verifier.py" dedup -i finding.json -o finding.json
```

最后读 `finding.json` 就是审查结果。

### 两种方式的区别

| | 方式 A（/code-review） | 方式 B（--scripted CLI） |
| --- | --- | --- |
| 判定质量 | 真 LLM 判断，更准 | 简单启发式，仅作兜底 |
| 消耗 | 花 token | 零 token |
| 用途 | 真实审查 / 比赛 | 干跑、自测、CI |

---

## 输出说明

管线在**当前目录**依次产出中间文件：

| 文件 | 产出方 | 内容 |
| --- | --- | --- |
| `change.json` | ① Collector | 本次变更集（文件 + hunk） |
| `impact_map.json` | ② Analyzer | 每文件技术栈 / 风险类别 / 该试哪些规则 |
| `candidate.json` | ③ Signal | 潜在漏洞候选 + 脱敏证据窗口 |
| `review_plan.json` | ④ Router | 哪些静态结案 / 哪些进 Reviewer / 哪些跳过 |
| `review_pack.json` | ⑤ build | 初审员看的证据包（LLM 输入） |
| `review_answers.json` | 你的判定 | 初审员逐条 verdict |
| `verification_pack.json` | ⑥ build | 复核员看的证据包（LLM 输入） |
| `verification_answers.json` | 你的判定 | 复核员逐条三态 verdict |
| **`finding.json`** | ⑥⑦ 终态 | **最终审查结果** |

`finding.json` 结构：

- `meta.counts`：总漏洞数、confirm / escalate / 被拒数、去重合并数、两个预算的使用情况（token 消耗）。
- `findings[]`：每条漏洞含 `pattern`（如 `sql_concat`）、`cwe`（如 CWE-89）、`severity`（high/medium/low）、`file` / `line` / `line_span`、`verdict`、`evidence`（证据）、`fix_hint`（修法）。
- `rejected[]`：被拒候选附录（初审拒 + 复核拒），用于排查误报。

**verdict 含义**（M7 三态）：

| verdict | 含义 | 处置 |
| --- | --- | --- |
| `CONFIRMED` | 复核确认是漏洞 | 保留，进报告 |
| `ESCALATE` | 证据不足以定论，需深度复核 | 保留但标记，人工再看一眼 |
| `REJECT` | 误报，被推翻 | 撤销，记入附录 |

静态结案（如硬编码密钥、debug=True）直接出 `CONFIRMED`（来源 `CONFIRMED_BY_RULE`，0 token）；语义类（SQL 注入、越权、SSRF…）经初审+复核两轮 LLM 判定。

---

## 常见问题

**必须在 git 仓库里跑吗？**
是。① Collector 靠 git 拿到变更集。在仓库根目录执行最稳妥。

**产物跑到哪去了？**
当前目录。默认文件名如上表；也可用 `-o 自定义.json` 改名。

**Windows 下中文显示乱码？**
只是终端编码问题（控制台是 GBK，文件是 UTF-8）。文件内容是正确的，用编辑器打开即可；脚本内打印用 `PYTHONIOENCODING=utf-8` 可对齐显示（注意测试脚本别加这个，会因 subprocess 解码不一致报错）。

**某一阶段报错怎么办？**
静态管线是逐条命令，哪条失败就看哪条的 stderr。常见是：不在 git 仓库、`change.json` 未生成就跑了下一步、文件名写错。

**想先试一把？**
M8 的 50 个靶场样本（30 漏洞 + 20 干净）就是现成测试对象：
```bash
cd code-review/tests
python ../../tests/m7/run_tests.py   # 全量回归 184 断言（M7 单里程碑）
```

---

## 当前状态与下一步

- **已完成**：M1 骨架+靶场 → M8 A01~A10 扩展，回归 **810/810**（M2 34 / 桥 100 / M3 80 / M4 182 / M5 86 / M6 144 / M7 184）。规则 27 条，覆盖 OWASP Top 10:2025 官方 A01~A10。
- **进行中**：⑧ 报告（人类可读 Markdown 摘要）与 M9（Extra + Token 优化）为蓝图。
- 设计定稿见 [docs/workflow-design-locked.md](docs/workflow-design-locked.md)，数据契约见 [code-review/schemas/](code-review/schemas/)。
