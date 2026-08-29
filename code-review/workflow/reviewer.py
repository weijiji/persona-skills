#!/usr/bin/env python3
"""
M6 Security Reviewer — 管线⑤：候选 + 规则口径 → finding.json（第一个 LLM 阶段）。

用法:
    python workflow/reviewer.py build  -r review_plan.json -c candidate.json -o review_pack.json
        # 只审 review_ids，打包成有界证据包（rule_ask + evidence + context），按预算分批
    python workflow/reviewer.py review -r review_plan.json -c candidate.json \
            --answers review_answers.json -o finding.json
        # 真实运行：Claude 读 review_pack.json 判定后写 review_answers.json，本命令校验+合并
    python workflow/reviewer.py review -r review_plan.json -c candidate.json \
            --scripted -o finding.json
        # 确定性兜底判定（测试 / 无 LLM / 干跑），产出 review_pack 与最终 finding

设计约束（design-locked §3 ⑤ / R5 / R7 / ADR-0003）:
  - 只审 review_ids：Signal 锚定、已脱敏的证据窗口（evidence + 有界 context）。
    LLM 永远不看完整 diff；密钥原文/生成代码/二进制/无关文件四类禁入（M4 已 scrub）。
  - Context Budget 硬约束 max_review_tokens=12000：估算提示 token，超预算自动分批（R7
    永不静默截断）；单条候选自身超限的显式记录进 oversized。
  - 判定结构化：每条 verdict(confirm/reject) + cwe/severity/reason/fix_hint。
    finalize 校验答案完整性后，与 M5 静态结案（findings_static）合并 → finding.json；
    reviewer 判 reject 的候选进 rejected 附录（R13），供 FPR 调优。
  - --scripted 是确定性兜底判定，仅用于测试/干跑；真实运行由 Skill 指示 Claude 做判定。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# 常量与系统口径（LLM 提示）
# --------------------------------------------------------------------------

DEFAULT_BUDGET = 12000        # R5 max_review_tokens
SAFETY_MARGIN = 0.85          # 留出回答 token 余量

SYSTEM = (
    "你是安全审查员。针对每条候选，依据其规则口径（rule_ask）与证据窗口"
    "（evidence/context）判定是否构成真实、可利用的安全漏洞。\n"
    "判定要点：\n"
    "- 需要「攻击者可控制的数据」实际到达「危险接收器」，且缺少有效缓解"
    "（参数化查询、转义、鉴权、CSRF 令牌等）。\n"
    "- 纯字面量常量即使出现在接收器旁也不构成漏洞（无用户输入路径）。\n"
    "- 证据指向真实可利用路径时 confirm；证据不足或已被缓解时 reject，宁缺勿滥。\n"
    "对每条候选输出一个 JSON 对象：{\"review_id\", \"verdict\": \"confirm\"|\"reject\", "
    "\"cwe\", \"severity\": \"high\"|\"medium\"|\"low\", \"reason\", \"fix_hint\"}。"
)


def estimate_tokens(text: str) -> int:
    """粗略估算提示 token：字符数 ÷4（代码偏密，取保守下限）。"""
    return max(1, len(text) // 4)


def load_registry() -> dict[str, dict]:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "rules", "registry.json"), encoding="utf-8") as f:
        return {r["name"]: r for r in json.load(f)["rules"]}


# --------------------------------------------------------------------------
# 打包：review_ids → 有界证据包（预算分批）
# --------------------------------------------------------------------------

def _pack_batches(items: list[dict], budget: int) -> tuple[list[list[dict]], list[str]]:
    """贪心分批：每批估算提示 token ≤ budget*SAFETY；单条自身超限 → 独立批并记录 oversized。"""
    limit = max(1, int(budget * SAFETY_MARGIN))
    batches: list[list[dict]] = []
    cur: list[dict] = []
    cur_tok = 0
    oversized: list[str] = []
    for it in items:
        tok = estimate_tokens(json.dumps(it, ensure_ascii=False))
        if tok > limit:
            oversized.append(it["review_id"])
            if cur:
                batches.append(cur)
                cur, cur_tok = [], 0
            batches.append([it])
            continue
        if cur and cur_tok + tok > limit:
            batches.append(cur)
            cur, cur_tok = [], 0
        cur.append(it)
        cur_tok += tok
    if cur:
        batches.append(cur)
    return batches, oversized


def build_pack(review_plan: dict, candidate: dict, registry: dict,
               budget: int = DEFAULT_BUDGET) -> dict:
    """review_plan.review_ids → 证据包。返回 {meta, system, batches}。"""
    cand_by_id = {c["candidate_id"]: c for c in candidate.get("candidates", [])}
    items: list[dict] = []
    missing: list[str] = []
    for rid in review_plan.get("review_ids", []):
        c = cand_by_id.get(rid)
        if c is None:
            missing.append(rid)          # 契约破损：候选丢失，显式记录不静默吞
            continue
        rule = registry.get(c.get("pattern", ""), {})
        rv = rule.get("review", {}) or {}
        items.append({
            "review_id": rid,
            "candidate_id": c["candidate_id"],
            "category": c["category"],
            "pattern": c["pattern"],
            "cwe": rule.get("cwe") or c.get("category") or "",
            "rule_ask": rv.get("ask", ""),
            "fix_hint": rv.get("fix", ""),
            "file": c["file"],
            "line": c["line"],
            "confidence": c.get("confidence", "medium"),
            "evidence": c.get("evidence", []),
            "context": c.get("context", ""),
        })
    batches, oversized = _pack_batches(items, budget)
    total_tok = sum(estimate_tokens(json.dumps(it, ensure_ascii=False)) for it in items)
    return {
        "meta": {
            "source_review_plan": "review_plan.json",
            "source_candidate": "candidate.json",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "review_count": len(items),
            "budget_tokens": budget,
            "estimated_prompt_tokens": total_tok,
            "batch_count": len(batches),
            "within_budget": total_tok <= budget,
            "oversized": oversized,
            "missing_candidates": missing,
        },
        "system": SYSTEM,
        "batches": batches,
    }


# --------------------------------------------------------------------------
# 确定性兜底判定（无 LLM，测试/干跑）
# --------------------------------------------------------------------------

SCRIPTED_SEVERITY = {
    "idor_missing_scope_check": "high",
    "ssrf_user_url": "high",
    "sql_concat": "high",
    "command_concat": "high",
    "eval_injection": "high",
    "xss_innerHTML": "medium",
    "weak_crypto": "medium",
    "weak_rng": "low",
}


def judge_scripted(item: dict) -> dict:
    """简单启发式：有危险接收器 + 无缓解 → confirm；否则 reject。
    仅测试/干跑用，不代表真实 LLM 判断。"""
    ev = {e.get("kind"): e.get("value") for e in item.get("evidence", [])}
    if ev.get("sanitizer") and ev["sanitizer"] not in ("none", "?", ""):
        return {"review_id": item["review_id"], "verdict": "reject",
                "reason": f"已有缓解（sanitizer={ev['sanitizer']}）", "fix_hint": ""}
    if ev.get("auth") and ev["auth"] not in ("none",):
        return {"review_id": item["review_id"], "verdict": "reject",
                "reason": "已有鉴权/防护", "fix_hint": ""}
    if not (ev.get("sink") or ev.get("user_controlled")):
        return {"review_id": item["review_id"], "verdict": "reject",
                "reason": "证据不足：未见数据到达危险接收器", "fix_hint": ""}
    return {
        "review_id": item["review_id"], "verdict": "confirm",
        "cwe": item.get("cwe", ""), "severity": SCRIPTED_SEVERITY.get(item.get("pattern"), "medium"),
        "reason": "确定性兜底判定：危险接收器 + 可控数据 + 无缓解（脚本模式）",
        "fix_hint": item.get("fix_hint", ""),
    }


# --------------------------------------------------------------------------
# 合并：静态结案 + Reviewer 判定 → finding.json
# --------------------------------------------------------------------------

def finalize(review_plan: dict, pack: dict, answers: list[dict]) -> dict:
    """校验 answers 并合并 findings_static → {meta, findings, rejected}。"""
    by_id = {a["review_id"]: a for a in answers}
    if len(by_id) != len(answers):
        raise ValueError("review_answers 存在重复 review_id")
    expected = {it["review_id"] for b in pack.get("batches", []) for it in b}
    missing = expected - set(by_id)
    if missing:
        raise ValueError(f"review_answers 缺 {len(missing)} 条：{sorted(missing)}")
    extra = set(by_id) - expected
    if extra:
        raise ValueError(f"review_answers 含未知 review_id：{sorted(extra)}")

    for a in answers:
        if a.get("verdict") not in ("confirm", "reject"):
            raise ValueError(f"{a['review_id']} verdict 非法：{a.get('verdict')}")
        if a.get("verdict") == "confirm":
            if a.get("severity") not in ("high", "medium", "low"):
                raise ValueError(f"{a['review_id']} confirm 缺合法 severity：{a.get('severity')}")
            if not a.get("cwe"):
                raise ValueError(f"{a['review_id']} confirm 缺 cwe")

    item_by_id = {it["review_id"]: it for b in pack.get("batches", []) for it in b}
    findings = list(review_plan.get("findings_static", []))
    rejected: list[dict] = []
    for a in answers:
        it = item_by_id.get(a["review_id"]) or {}
        base = {
            "finding_id": f"F-{a['review_id']}",
            "candidate_id": it.get("candidate_id", a["review_id"]),
            "category": it.get("category", ""),
            "pattern": it.get("pattern", ""),
            "cwe": a.get("cwe") or it.get("cwe", ""),
            "file": it.get("file", ""),
            "line": it.get("line", 0),
            "severity": a.get("severity", "medium"),
            "confidence": it.get("confidence", "medium"),
        }
        if a["verdict"] == "confirm":
            findings.append({
                **base,
                "verdict": "CONFIRMED_BY_REVIEWER",
                "evidence": it.get("evidence", []),
                "context": it.get("context", ""),
                "reason": a.get("reason", ""),
                "fix_hint": a.get("fix_hint") or it.get("fix_hint", ""),
            })
        else:
            rejected.append({
                "review_id": a["review_id"],
                "candidate_id": it.get("candidate_id", a["review_id"]),
                "pattern": it.get("pattern", ""),
                "category": it.get("category", ""),
                "file": it.get("file", ""),
                "line": it.get("line", 0),
                "reason": a.get("reason", ""),
                "evidence": it.get("evidence", []),
            })

    findings.sort(key=lambda f: (f["category"], f["pattern"], f["file"], f["line"]))
    confirm_n = sum(1 for a in answers if a["verdict"] == "confirm")
    return {
        "meta": {
            "source_review_plan": pack.get("meta", {}).get("source_review_plan", "review_plan.json"),
            "source_review_pack": "review_pack.json",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "counts": {
                "total": len(findings),
                "static": len(review_plan.get("findings_static", [])),
                "reviewer_confirm": confirm_n,
                "reviewer_reject": len(rejected),
                "rejected_total": len(rejected),
            },
            "review_budget": {
                "max_tokens": pack.get("meta", {}).get("budget_tokens", DEFAULT_BUDGET),
                "estimated_prompt_tokens": pack.get("meta", {}).get("estimated_prompt_tokens", 0),
                "batch_count": pack.get("meta", {}).get("batch_count", 0),
                "within_budget": pack.get("meta", {}).get("within_budget", True),
            },
        },
        "findings": findings,
        "rejected": rejected,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cmd_build(args) -> int:
    review_plan = _load(args.review_plan)
    candidate = _load(args.candidate)
    pack = build_pack(review_plan, candidate, load_registry(), budget=args.budget)
    pack["meta"]["source_review_plan"] = os.path.basename(args.review_plan)
    pack["meta"]["source_candidate"] = os.path.basename(args.candidate)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(pack, f, indent=2, ensure_ascii=False)
    m = pack["meta"]
    print(f"[reviewer] review={m['review_count']} batches={m['batch_count']} "
          f"tokens~{m['estimated_prompt_tokens']}/{m['budget_tokens']} "
          f"oversized={m['oversized']} → {args.output}")
    return 0


def cmd_review(args) -> int:
    if bool(args.scripted) == bool(args.answers):
        print("错误：必须且只能选 --scripted 或 --answers 之一", file=sys.stderr)
        return 2
    review_plan = _load(args.review_plan)
    candidate = _load(args.candidate)
    pack = build_pack(review_plan, candidate, load_registry(), budget=args.budget)
    if args.scripted:
        items = [it for b in pack["batches"] for it in b]
        answers = [judge_scripted(it) for it in items]
    else:
        answers = _load(args.answers)["answers"]
    finding = finalize(review_plan, pack, answers)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(finding, f, indent=2, ensure_ascii=False)
    m = finding["meta"]
    print(f"[reviewer] findings={m['counts']['total']} "
          f"(static={m['counts']['static']} reviewer_confirm={m['counts']['reviewer_confirm']} "
          f"reject={m['counts']['reviewer_reject']}) batches={m['review_budget']['batch_count']} "
          f"→ {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Security Reviewer → finding.json（管线⑤，首个 LLM 阶段）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="候选 + 规则口径 → review_pack.json（LLM 输入，按预算分批）")
    b.add_argument("-r", "--review-plan", default="review_plan.json")
    b.add_argument("-c", "--candidate", default="candidate.json")
    b.add_argument("-o", "--output", default="review_pack.json")
    b.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    b.set_defaults(fn=cmd_build)

    rv = sub.add_parser("review", help="判定 + 合并 → finding.json")
    rv.add_argument("-r", "--review-plan", default="review_plan.json")
    rv.add_argument("-c", "--candidate", default="candidate.json")
    rv.add_argument("-o", "--output", default="finding.json")
    rv.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    rv.add_argument("--answers", help="Claude 判定产出的 review_answers.json")
    rv.add_argument("--scripted", action="store_true", help="用确定性兜底判定（无 LLM）")
    rv.set_defaults(fn=cmd_review)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
