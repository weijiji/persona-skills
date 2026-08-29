# ADR-0001: 先建 Test Corpus，再写 Rule

为确保 Workflow 可度量，决定在实现任何检测 Rule 之前，先为每个 A0x 类别建立 positive / negative 测试样本（即 Ground Truth）。没有 Ground Truth 就无法计算 Recall / FPR，方案是否有效只能靠"Prompt 看起来很厉害"来主观判断，无法迭代。

**Status**: accepted

**Considered Options**:
- 先写 30~50 条 Rule 再补测试 —— 被否：每新增一条 Rule 都无法即时度量它对 Recall / FPR 的贡献，开发是盲的。

**Consequences**:
- M1 阶段需额外投入搭建靶场（`tests/A0x/{positive,negative}`）。
- 换来可量化的迭代循环：每轮跑出 Recall / FPR / Token Cost 仪表盘，用 Ground Truth 驱动规则扩展。

相关术语见 [[CONTEXT.md]] 的 Test Corpus / Ground Truth / Recall / False Positive Rate。
