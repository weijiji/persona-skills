#!/usr/bin/env python3
"""
M7 Verifier + Dedup — 管线⑥⑦：对抗式三态复核 + 去重合并 → finding.json 终态。

用法:
    python workflow/verifier.py build  -i finding.json -o verification_pack.json
        # ⑥ 复核证据包：把 M6 的 finding 包成有界对抗复核窗口，max_verification_tokens=5000 分批
    python workflow/verifier.py verify -i finding.json --answers verification_answers.json -o finding.json
        # 真实运行：Claude 读 verification_pack.json 判 confirm/reject/escalate，写 verification_answers.json
    python workflow/verifier.py verify -i finding.json --scripted -o finding.json
        # 确定性兜底判定（测试 / 无 LLM / 干跑）
    python workflow/verifier.py dedup  -i finding.json -o finding.json
        # ⑦ 按 key=(file, line_span, cwe) 合并重复漏洞

设计约束（design-locked §3 ⑥⑦ / R10 / R5 / ADR-0003）:
  - ⑥ Verifier 对抗式复核：对每条 finding 尝试推翻它（假阳性 / 初审遗漏的缓解 / 数据不可达），
    三态 verdict CONFIRMED / REJECT / ESCALATE。仅 ESCALATE 追加 token 深度复核——本阶段
    ESCALATE 保留为 finding 并标记，深度复核在真实流程由 Skill 指示 Claude 扩大窗口做。
  - ⑥ 只复核 finding.json 里的 findings（rejected 附录不再复核）；LLM 仍只见有界、已脱敏窗口。
  - ⑦ Dedup：key=(file, line_span, cwe)，span 重叠或相邻(≤GAP 行)的重复漏洞合并为一条。
  - Context Budget 硬约束 max_verification_tokens=5000：超预算自动分批（R7 不静默截断），
    单条自身超限的显式记录进 oversized。
  - --scripted 是确定性兜底判定，仅测试/干跑；真实判定由 Skill 指示 Claude 做。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# 同目录共享的估 token，避免与 M6 口径漂移（reviewer 不 import 本模块，无环）。
from reviewer import estimate_tokens  # noqa: E402

DEFAULT_VERIFY_BUDGET = 5000        # R5 max_verification_tokens
GAP = 2                             # dedup 相邻合并容忍行数
SAFETY_MARGIN = 0.85                # 留出回答 token 余量（与 M6 一致）

VERIFY_SYSTEM = (
    "你是对抗式安全复核员。针对每条已通过初审的 finding，你的任务不是重复确认，而是尝试推翻它"
    "——寻找让它成为假阳性的理由。\n"
    "对抗要点：\n"
    "- 攻击者可控的数据是否真的能到达危险接收器？还是死代码 / 测试代码 / 示例 / 未接线路由？\n"
    "- 是否有初审遗漏的缓解：参数化查询、转义、鉴权、CSRF 令牌、内部白名单、输入清洗？\n"
    "- 漏洞是否真实可利用，还是静态巧合（纯字面量、被覆盖的变量、未使用参数）？\n"
    "三态输出：\n"
    "- confirm：维持漏洞，确实可利用。\n"
    "- reject：假阳性，撤销该 finding。\n"
    "- escalate：证据不足以定论（窗口太窄 / 需跨函数看数据流），追加深度复核。\n"
    "对每条 finding 输出一个 JSON 对象：{\"finding_id\", \"verdict\": \"confirm\"|\"reject\"|\"escalate\", "
    "\"reason\"}；confirm 时可选给出覆盖的 {\"cwe\", \"severity\"}。宁缺勿滥：找不到可利用路径就 reject。"
)


def load_registry() -> dict[str, dict]:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "rules", "registry.json"), encoding="utf-8") as f:
        return {r["name"]: r for r in json.load(f)["rules"]}


# --------------------------------------------------------------------------
# ⑥ 打包：findings → 有界对抗复核证据包（预算分批）
# --------------------------------------------------------------------------

def _pack_batches(items: list[dict], budget: int) -> tuple[list[list[dict]], list[str]]:
    """贪心分批（镜像 reviewer._pack_batches，但按 finding_id 记 oversized）。"""
    limit = max(1, int(budget * SAFETY_MARGIN))
    batches: list[list[dict]] = []
    cur: list[dict] = []
    cur_tok = 0
    oversized: list[str] = []
    for it in items:
        tok = estimate_tokens(json.dumps(it, ensure_ascii=False))
        if tok > limit:
            oversized.append(it["finding_id"])
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


def build_verification_pack(finding: dict, registry: dict,
                            budget: int = DEFAULT_VERIFY_BUDGET) -> dict:
    """把 finding.json 的 findings 包成复核窗口。返回 {meta, system, batches}。"""
    items: list[dict] = []
    missing_rules: list[str] = []
    for f in finding.get("findings", []):
        rule = registry.get(f.get("pattern", ""), {})
        rv = rule.get("review", {}) or {}
        if not rule:
            missing_rules.append(f.get("pattern", ""))
        items.append({
            "finding_id": f["finding_id"],
            "category": f.get("category", ""),
            "pattern": f.get("pattern", ""),
            "cwe": f.get("cwe", ""),
            "severity": f.get("severity", "medium"),
            "confidence": f.get("confidence", "medium"),
            "origin_verdict": f.get("verdict", ""),
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "rule_ask": rv.get("ask", ""),
            "fix_hint": rv.get("fix", ""),
            "evidence": f.get("evidence", []),
            "context": f.get("context", ""),
        })
    batches, oversized = _pack_batches(items, budget)
    total_tok = sum(estimate_tokens(json.dumps(it, ensure_ascii=False)) for it in items)
    return {
        "meta": {
            "source_finding": "finding.json",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "verification_count": len(items),
            "budget_tokens": budget,
            "estimated_prompt_tokens": total_tok,
            "batch_count": len(batches),
            "within_budget": total_tok <= budget,
            "oversized": oversized,
            "missing_rules": sorted(set(missing_rules)),
        },
        "system": VERIFY_SYSTEM,
        "batches": batches,
    }


# --------------------------------------------------------------------------
# ⑥ 确定性兜底对抗复核（无 LLM，测试/干跑）
# --------------------------------------------------------------------------

def verify_scripted(item: dict) -> dict:
    """已缓解 / 无验证锚点 → reject；中等置信 → escalate；否则 confirm。"""
    ev = {e.get("kind"): e.get("value") for e in item.get("evidence", [])}
    if ev.get("sanitizer") and ev["sanitizer"] not in ("none", "?", ""):
        return {"finding_id": item["finding_id"], "verdict": "reject",
                "reason": f"已缓解（sanitizer={ev['sanitizer']}）"}
    if ev.get("auth") and ev["auth"] not in ("none",):
        return {"finding_id": item["finding_id"], "verdict": "reject",
                "reason": "已有鉴权/防护"}
    if not any(ev.get(k) for k in ("sink", "user_controlled", "config", "endpoint")):
        return {"finding_id": item["finding_id"], "verdict": "reject",
                "reason": "无验证锚点：未见危险接收器/可控数据/配置信号"}
    if item.get("confidence") == "medium":
        return {"finding_id": item["finding_id"], "verdict": "escalate",
                "reason": "静态置信中等：追加深度复核"}
    return {"finding_id": item["finding_id"], "verdict": "confirm",
            "reason": "确定性对抗复核：锚点齐全且无缓解（脚本模式）"}


# --------------------------------------------------------------------------
# ⑥ 合并：三态 verdict 应用 + 校验 + 保留 provenance
# --------------------------------------------------------------------------

def apply_verdicts(finding: dict, pack: dict, answers: list[dict]) -> dict:
    """校验 verification_answers 并应用三态 verdict → 复核后 finding 文档。"""
    by_id = {a["finding_id"]: a for a in answers}
    if len(by_id) != len(answers):
        raise ValueError("verification_answers 存在重复 finding_id")
    expected = {it["finding_id"] for b in pack.get("batches", []) for it in b}
    missing = expected - set(by_id)
    if missing:
        raise ValueError(f"verification_answers 缺 {len(missing)} 条：{sorted(missing)}")
    extra = set(by_id) - expected
    if extra:
        raise ValueError(f"verification_answers 含未知 finding_id：{sorted(extra)}")

    for a in answers:
        if a.get("verdict") not in ("confirm", "reject", "escalate"):
            raise ValueError(f"{a['finding_id']} verdict 非法：{a.get('verdict')}")
        if a.get("severity") not in (None, "high", "medium", "low"):
            raise ValueError(f"{a['finding_id']} severity 非法：{a.get('severity')}")
        if a.get("cwe") is not None and not str(a.get("cwe")).strip():
            raise ValueError(f"{a['finding_id']} cwe 为空")

    item_by_id = {it["finding_id"]: it for b in pack.get("batches", []) for it in b}
    orig_by_id = {f["finding_id"]: f for f in finding.get("findings", [])}

    rejected_out: list[dict] = []
    for r in finding.get("rejected", []):
        row = dict(r)
        row.setdefault("stage", "reviewer")
        rejected_out.append(row)

    out_findings: list[dict] = []
    rejected_by_verifier = 0
    for a in answers:
        if a["verdict"] == "reject":
            rejected_by_verifier += 1
            f = orig_by_id[a["finding_id"]]
            rejected_out.append({
                "finding_id": f["finding_id"],
                "candidate_id": f.get("candidate_id", ""),
                "pattern": f.get("pattern", ""),
                "category": f.get("category", ""),
                "cwe": f.get("cwe", ""),
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "verdict": "REJECT",
                "stage": "verifier",
                "reason": a.get("reason", ""),
                "evidence": f.get("evidence", []),
            })
            continue
        f = dict(orig_by_id[a["finding_id"]])
        f["verdict"] = "CONFIRMED" if a["verdict"] == "confirm" else "ESCALATE"
        f["origin_verdict"] = it_by_id_in(a, item_by_id)
        f["line_span"] = [f.get("line", 0), f.get("line", 0)]
        f["verifier_reason"] = a.get("reason", "")
        if a.get("cwe"):
            f["cwe"] = a["cwe"]
        if a.get("severity"):
            f["severity"] = a["severity"]
        out_findings.append(f)

    out_findings.sort(key=lambda x: (x.get("category", ""), x.get("pattern", ""),
                                     x.get("file", ""), x.get("line", 0)))
    in_counts = finding.get("meta", {}).get("counts", {})
    return {
        "meta": {
            "source_finding": pack.get("meta", {}).get("source_finding", "finding.json"),
            "source_verification_pack": "verification_pack.json",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "counts": {
                "total": len(out_findings),
                "confirmed": sum(1 for x in out_findings if x["verdict"] == "CONFIRMED"),
                "escalated": sum(1 for x in out_findings if x["verdict"] == "ESCALATE"),
                "rejected": len(rejected_out),
                "rejected_by_verifier": rejected_by_verifier,
                "dedup_merged": 0,
                "static": in_counts.get("static", 0),
                "reviewer_confirm": in_counts.get("reviewer_confirm", 0),
            },
            "review_budget": finding.get("meta", {}).get("review_budget", {}),
            "verification_budget": {
                "max_tokens": pack.get("meta", {}).get("budget_tokens", DEFAULT_VERIFY_BUDGET),
                "estimated_prompt_tokens": pack.get("meta", {}).get("estimated_prompt_tokens", 0),
                "batch_count": pack.get("meta", {}).get("batch_count", 0),
                "within_budget": pack.get("meta", {}).get("within_budget", True),
            },
        },
        "findings": out_findings,
        "rejected": rejected_out,
    }


def it_by_id_in(a: dict, item_by_id: dict) -> str:
    return item_by_id.get(a["finding_id"], {}).get("origin_verdict", "")


# --------------------------------------------------------------------------
# ⑦ Dedup：key=(file, line_span, cwe) 去重合并
# --------------------------------------------------------------------------

SEV_ORDER = {"low": 0, "medium": 1, "high": 2}
CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


def _merge_two(a: dict, b: dict) -> dict:
    """把 b 并入 a（a 为已合并的累计条目），保留更严重/更高置信/更完整的证据。"""
    out = dict(a)
    if SEV_ORDER.get(b.get("severity", "low"), 0) > SEV_ORDER.get(a.get("severity", "low"), 0):
        out["severity"] = b["severity"]
    if CONF_ORDER.get(b.get("confidence", "low"), 0) > CONF_ORDER.get(a.get("confidence", "low"), 0):
        out["confidence"] = b["confidence"]
    seen_ev = {(e.get("kind"), e.get("value")) for e in a.get("evidence", [])}
    ev = list(a.get("evidence", []))
    for e in b.get("evidence", []):
        if (e.get("kind"), e.get("value")) not in seen_ev:
            ev.append(e)
            seen_ev.add((e.get("kind"), e.get("value")))
    out["evidence"] = ev
    reasons = [r for r in (a.get("reason"), b.get("reason")) if r]
    out["reason"] = " | ".join(dict.fromkeys(reasons))
    vrs = [r for r in (a.get("verifier_reason"), b.get("verifier_reason")) if r]
    out["verifier_reason"] = " | ".join(dict.fromkeys(vrs))
    out["verdict"] = "ESCALATE" if "ESCALATE" in {a.get("verdict"), b.get("verdict")} else "CONFIRMED"
    as_, bs_ = a["line_span"], b["line_span"]
    out["line_span"] = [min(as_[0], bs_[0]), max(as_[1], bs_[1])]
    out["line"] = out["line_span"][0]
    if len(b.get("context", "")) > len(a.get("context", "")):
        out["context"] = b["context"]
    out["candidate_id"] = a.get("candidate_id") or b.get("candidate_id")
    return out


def dedup_findings(findings: list[dict]) -> tuple[list[dict], int]:
    """按 (file, cwe) 分组；line_span 重叠或相邻(≤GAP) 视为同一漏洞，合并。返回 (结果, 合并掉数量)。"""
    groups: dict[tuple[str, str], list[dict]] = {}
    for f in findings:
        groups.setdefault((f.get("file"), f.get("cwe")), []).append(f)
    out: list[dict] = []
    merged = 0
    for key in sorted(groups):
        fs = sorted(groups[key], key=lambda f: (f["line_span"][0], f.get("line", 0)))
        cur = dict(fs[0])
        for f in fs[1:]:
            if f["line_span"][0] <= cur["line_span"][1] + GAP:
                cur = _merge_two(cur, f)
                merged += 1
            else:
                out.append(cur)
                cur = dict(f)
        out.append(cur)
    out.sort(key=lambda x: (x.get("category", ""), x.get("pattern", ""),
                            x.get("file", ""), x.get("line", 0)))
    return out, merged


def dedup_doc(verified: dict) -> dict:
    """复核后 finding 文档 → 去重终态（normalize line_span + 更新计数）。"""
    findings = []
    for f in verified.get("findings", []):
        row = dict(f)
        if not row.get("line_span"):
            l = row.get("line", 0)
            row["line_span"] = [l, l]
        findings.append(row)
    out, merged = dedup_findings(findings)
    meta = dict(verified.get("meta", {}))
    counts = dict(meta.get("counts", {}))
    counts["total"] = len(out)
    counts["dedup_merged"] = merged
    meta["counts"] = counts
    meta["generated_at"] = datetime.now(timezone.utc).isoformat()
    return {"meta": meta, "findings": out, "rejected": verified.get("rejected", [])}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _dump(doc: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)


def cmd_build(args) -> int:
    pack = build_verification_pack(_load(args.input), load_registry(), budget=args.budget)
    pack["meta"]["source_finding"] = os.path.basename(args.input)
    _dump(pack, args.output)
    m = pack["meta"]
    print(f"[verifier] findings={m['verification_count']} batches={m['batch_count']} "
          f"tokens~{m['estimated_prompt_tokens']}/{m['budget_tokens']} "
          f"oversized={m['oversized']} → {args.output}")
    return 0


def cmd_verify(args) -> int:
    if bool(args.scripted) == bool(args.answers):
        print("错误：必须且只能选 --scripted 或 --answers 之一", file=sys.stderr)
        return 2
    finding = _load(args.input)
    pack = build_verification_pack(finding, load_registry(), budget=args.budget)
    if args.scripted:
        items = [it for b in pack["batches"] for it in b]
        answers = [verify_scripted(it) for it in items]
    else:
        answers = _load(args.answers)["answers"]
    verified = apply_verdicts(finding, pack, answers)
    _dump(verified, args.output)
    c = verified["meta"]["counts"]
    print(f"[verifier] findings={c['total']} (confirm={c['confirmed']} escalate={c['escalated']} "
          f"reject={c['rejected_by_verifier']}) → {args.output}")
    return 0


def cmd_dedup(args) -> int:
    final = dedup_doc(_load(args.input))
    _dump(final, args.output)
    c = final["meta"]["counts"]
    print(f"[verifier] dedup merged={c['dedup_merged']} findings={c['total']} → {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verifier + Dedup → finding.json 终态（管线⑥⑦）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="findings → verification_pack.json（对抗复核输入，按预算分批）")
    b.add_argument("-i", "--input", default="finding.json")
    b.add_argument("-o", "--output", default="verification_pack.json")
    b.add_argument("--budget", type=int, default=DEFAULT_VERIFY_BUDGET)
    b.set_defaults(fn=cmd_build)

    v = sub.add_parser("verify", help="三态 verdict 应用 → 复核后 finding 文档")
    v.add_argument("-i", "--input", default="finding.json")
    v.add_argument("-o", "--output", default="finding.json")
    v.add_argument("--budget", type=int, default=DEFAULT_VERIFY_BUDGET)
    v.add_argument("--answers", help="Claude 判定产出的 verification_answers.json")
    v.add_argument("--scripted", action="store_true", help="用确定性兜底对抗复核（无 LLM）")
    v.set_defaults(fn=cmd_verify)

    d = sub.add_parser("dedup", help="(file, line_span, cwe) 去重合并 → 终态 finding 文档")
    d.add_argument("-i", "--input", default="finding.json")
    d.add_argument("-o", "--output", default="finding.json")
    d.set_defaults(fn=cmd_dedup)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
