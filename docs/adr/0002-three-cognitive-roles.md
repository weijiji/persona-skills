# ADR-0002: 第一版只设 3 个认知角色，不做按类别拆分的 Agent

决定第一版管线只包含 **Change Analyzer / Security Reviewer / Verifier** 三个认知角色，而不是为 A01~A10 各设一个 Agent，也不做多 Agent swarm。每个 LLM 角色都是一次推理与一份 token 成本；Signal Engine 和 Risk Router 承担绝大部分筛选，让 LLM 只处理"值得判断"的 Candidate。

**Status**: accepted

**Considered Options**:
- 10 个类别 Agent（A01~A10 各一个）—— 被否：token 成本成倍上升，类别间共享上下文变差；第一版目标是验证管线而非最大化并行覆盖。
- 多 Agent swarm —— 被否：复杂度和 token 成本远超 M1~M7 需要，见设计文档 Step 9 的"第一版不做"清单。

**Consequences**:
- 3 角色在 Python 编排中是**逻辑角色**，不必然等于 3 次独立模型调用——Signal 与 Router 尽量不走 LLM。
- 未来按 M8 扩充规则时，若某类信号误报过高，才考虑拆出专精角色。

相关：[[0001-test-corpus-first]]，术语见 [[CONTEXT.md]] 的 Signal / Candidate / Finding / Verifier / Risk Router。
