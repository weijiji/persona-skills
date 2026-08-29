# ADR-0003: LLM 只看 Signal 锚定的证据窗口，不读完整 diff

决定整条管线中 LLM 的输入永远是 Signal 引擎产出的 Candidate + 有界证据窗口，而不是原始 diff。Token 优化不靠"截断 diff"，而靠管线分工：grep/AST 便宜地扫完整变更，只有值得判断的点才消耗 LLM 推理。

**Status**: accepted

**Considered Options**:
- 直接把 diff 整体交给 LLM 审查 —— 被否：token 随 diff 行数线性增长，大变更下必然触发截断或超预算；且无结构的全量文本会稀释模型注意力，Recall 不升反降。

**Consequences**:
- 大 diff 下 token 成本不随 diff 行数线性增长（Signal 阶段是 grep，不是 LLM）。
- Signal Engine 的质量成为 Recall 的天花板：信号没命中，LLM 永远不会看到那里。因此 Test Corpus 驱动下，**扩充 Rule 的优先级高于任何 Prompt 调优**。
- "永不静默截断"因此可行：LLM 本就只看证据窗口，超大 diff 只会影响 Signal 阶段，不会让预算失控。

相关：[[0002-three-cognitive-roles]]，术语见 [[CONTEXT.md]] 的 Signal / Candidate / Context Budget。
