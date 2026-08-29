#!/usr/bin/env python3
"""
M5 Risk Router — 管线④：三层规则路由 → review_plan.json（纯规则，0 LLM token）。

用法:
    python workflow/router.py -c candidate.json -o review_plan.json

设计约束（design-locked §3 ④ / R9）:
  - 路由非 LLM：只按「规则类别 × 置信度 × 证据」静态决策。
  - 静态结案为漏洞(finding)：字面量即漏洞的确定性规则（密钥/CORS/debug/弱凭据/
    未锁定依赖），0 token 直接产出 finding，不再进 Reviewer。
  - 语义进 Reviewer(review)：注入类 / A01 越权 / 弱加密弱随机数——需要 LLM 判断
    "被插值的数据是否用户可控 / 上下文是否安全"。
  - 低置信跳过(skip)：基于缺位的弱信号（无鉴权 / 无 CSRF / 无锁文件 / 非官方源），
    以及 sql_concat 的"变量参数"低置信命中。
  - 静态结案为无害(clean)：evidence 显示已有防护（sanitizer/鉴权）的候选直接否掉。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# 规则名 → 该规则字面量命中即确凿 → 静态结案
ROUTE_FINDING = {"hardcoded_secret", "permissive_cors", "debug_enabled",
                 "default_credentials", "unpinned_dependency"}
# 规则名 → 基于缺位的弱信号 → 低置信跳过
ROUTE_SKIP = {"handler_without_auth", "csrf_state_change", "missing_lockfile",
              "untrusted_registry"}
# 静态结案的严重度初判（M6 Reviewer 不处理这些，直接进报告）
STATIC_SEVERITY = {
    "hardcoded_secret": "high", "default_credentials": "high",
    "unpinned_dependency": "medium", "permissive_cors": "medium",
    "debug_enabled": "medium",
}

REASONS = {
    "finding": "静态结案：字面量即漏洞，0 token",
    "review": "语义待判：需 LLM 确认上下文",
    "skip": "低置信弱信号，跳过省 token",
    "clean": "静态结案：evidence 显示已有防护",
}


def decide(c: dict) -> tuple[str, str]:
    """单条候选的路由决策 → (decision, reason)。decision ∈ {finding, review, skip, clean}。"""
    pattern, conf = c.get("pattern", ""), c.get("confidence", "medium")
    for e in c.get("evidence", []):
        if e.get("kind") == "sanitizer" and e.get("value") not in ("none", "?", ""):
            return "clean", REASONS["clean"]
        if e.get("kind") == "auth" and e.get("value") and e["value"] not in ("none",):
            return "clean", REASONS["clean"]
    if pattern in ROUTE_FINDING and conf == "high":
        return "finding", REASONS["finding"]
    if pattern in ROUTE_SKIP:
        return "skip", REASONS["skip"]
    if conf == "low":
        return "skip", REASONS["skip"]
    return "review", REASONS["review"]


def load_registry() -> dict[str, dict]:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "rules", "registry.json"), encoding="utf-8") as f:
        return {r["name"]: r for r in json.load(f)["rules"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Risk Router → review_plan.json（管线④，纯规则）")
    ap.add_argument("-c", "--candidate", default="candidate.json")
    ap.add_argument("-o", "--output", default="review_plan.json")
    args = ap.parse_args(argv)

    with open(args.candidate, encoding="utf-8") as f:
        cand = json.load(f)
    registry = load_registry()

    decisions: list[dict] = []
    findings_static: list[dict] = []
    review_ids: list[str] = []
    counts = {"finding": 0, "review": 0, "skip": 0, "clean": 0}

    for c in cand.get("candidates", []):
        decision, reason = decide(c)
        counts[decision] += 1
        row = {"candidate_id": c["candidate_id"], "pattern": c["pattern"],
               "category": c["category"], "file": c["file"], "line": c["line"],
               "confidence": c["confidence"], "decision": decision, "reason": reason}
        decisions.append(row)
        if decision == "finding":
            cwe = registry.get(c["pattern"], {}).get("cwe")
            findings_static.append({
                "finding_id": f"F-{c['candidate_id']}",
                "candidate_id": c["candidate_id"],
                "category": c["category"], "pattern": c["pattern"], "cwe": cwe,
                "file": c["file"], "line": c["line"],
                # 静态结案只发生在 conf==high 的 ROUTE_FINDING 分支（见 decide），
                # 显式带 confidence 供 M7 Verifier 对抗复核使用。
                "confidence": c["confidence"],
                "severity": STATIC_SEVERITY.get(c["pattern"], "medium"),
                "verdict": "CONFIRMED_BY_RULE",
                "evidence": c.get("evidence", []),
                "context": c.get("context", ""),
            })
        elif decision == "review":
            review_ids.append(c["candidate_id"])

    out = {
        "meta": {"source_candidate": os.path.basename(args.candidate),
                 "generated_at": datetime.now(timezone.utc).isoformat(),
                 "counts": {"total": len(decisions), **counts}},
        "decisions": decisions,
        "findings_static": findings_static,
        "review_ids": review_ids,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f"[router] total={len(decisions)} {counts} review={len(review_ids)} "
          f"static_findings={len(findings_static)} → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
