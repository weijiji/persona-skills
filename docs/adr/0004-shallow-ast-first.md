# ADR-0004: 第一版 AST 只做句法邻接，不做完整数据流

决定 Signal Engine 的 AST 阶段第一版只做"句法邻接 + 函数边界"：命中是否在真实函数体内、被标记变量的函数内最小血缘（赋值→使用）、就近是否存在用户输入源 / 鉴权守卫 / 转义。**不做**完整数据流 / 污点分析。

**Status**: accepted

**Considered Options**:
- 第一版即上完整数据流/污点分析 —— 被否：实现成本高，跨语言 AST 复杂度爆炸；第一版目标是验证整条管线而非把单类精度推到极限，且 token 预算下 LLM 才是语义判断的主力。

**Consequences**:
- A01 / A05 的句法类假阳性会偏多，由 Verifier 三态（尤其 REJECT）兜底并记入 FPR 日志。
- M9 阶段若某类别 FPR 过高，针对**该类别**加深 AST（增量演进，不重构）。

相关：[[0002-three-cognitive-roles]]、[[0003-signal-anchored-evidence]]，术语见 [[CONTEXT.md]] 的 Signal / Verdict。
