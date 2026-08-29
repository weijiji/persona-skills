#!/usr/bin/env python3
"""
M6 Security Reviewer 验收测试（无第三方依赖，仅 git + python3）。

用法: python tests/m6/run_tests.py
逐项构建临时 git 仓库 → collect → analyze → signal → router → reviewer（--scripted 兜底判定）。
覆盖:
  T1 全量 positive 靶场：15 样本各产出 pattern 匹配、行号±1 的 finding
  T2 全量 negative 靶场：无匹配 pattern 的 finding
  T3 judge_scripted 决策：接收器+无缓解 → confirm；缓解/无接收器 → reject
  T4 build_pack 预算分批：超预算自动分批、单条超限显式记录（R7 不静默截断）
  T5 脱敏贯通：hardcoded_secret 密钥原文不进 finding.json
  T6 契约：字段 / verdict 枚举 / 计数闭合 / rejected 附录 / 空 review / CLI --answers 接线
  T7 finalize 校验：缺答 / 重复 / 未知 id / 非法 verdict → ValueError
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / "code-review" / "workflow"
COLLECTOR = WORKFLOW / "collect.py"
ANALYZER = WORKFLOW / "analyze.py"
SIGNAL = WORKFLOW / "signal_engine.py"
ROUTER = WORKFLOW / "router.py"
REVIEWER = WORKFLOW / "reviewer.py"
CORPUS = ROOT / "code-review" / "tests"

sys.path.insert(0, str(WORKFLOW))
from reviewer import build_pack, estimate_tokens, finalize, judge_scripted, load_registry  # noqa: E402

_results: list[bool] = []


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


def init_repo(cwd):
    git(cwd, "init", "-q")
    git(cwd, "config", "user.email", "m6@test")
    git(cwd, "config", "user.name", "M6Test")


def pipeline(cwd, files: dict[str, str], scripted: bool = True):
    """collect → analyze → signal → router → reviewer，返回 finding.json。"""
    for name, content in files.items():
        p = cwd / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    subprocess.run([sys.executable, str(COLLECTOR), "-o", "change.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(ANALYZER), "-i", "change.json", "-o", "impact_map.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(SIGNAL), "-c", "change.json",
                    "-m", "impact_map.json", "-o", "candidate.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(ROUTER), "-c", "candidate.json", "-o", "review_plan.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    args = [sys.executable, str(REVIEWER), "review", "-r", "review_plan.json",
            "-c", "candidate.json", "-o", "finding.json", "--scripted"]
    subprocess.run(args, cwd=str(cwd), check=True, capture_output=True, text=True)
    return json.loads((cwd / "finding.json").read_text(encoding="utf-8"))


def check(name, cond, detail=""):
    _results.append(bool(cond))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def repo(tmp, name):
    d = tmp / name
    d.mkdir(exist_ok=True)
    init_repo(d)
    git(d, "commit", "--allow-empty", "-qm", "init")
    return d


def corpus_code(d: Path):
    return sorted(f for f in d.iterdir()
                  if f.name != "annotation.json"
                  and (f.suffix in {".py", ".json", ".txt"} or f.name.lower() == "dockerfile"))


# ---------------------------------------------------------------------------
# T1 / T2：全量靶场贯通
# ---------------------------------------------------------------------------

def t1_positives(tmp):
    print("T1 全量 positive 靶场：每样本产出匹配 finding")
    for cat in ["A01", "A02", "A03", "A04", "A05"]:
        base = CORPUS / cat / "positive"
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            ann = json.loads((d / "annotation.json").read_text(encoding="utf-8"))
            code = corpus_code(d)
            r = repo(tmp, f"p-{ann['sample_id']}")
            (r / code[0].name).write_bytes(code[0].read_bytes())
            try:
                finding = pipeline(r, {})
            except subprocess.CalledProcessError as e:
                check(f"{ann['sample_id']} 管线可跑", False, e.stderr[-300:])
                continue
            fs = finding["findings"]
            matches = [x for x in fs if x["pattern"] == ann["pattern"]]
            check(f"{ann['sample_id']} 产出 {ann['pattern']} finding",
                  bool(matches), f"got {[x['pattern'] for x in fs]}")
            if matches:
                check(f"{ann['sample_id']} 行号±1（标注 {ann['lines']}）",
                      any(abs(x["line"] - ann["lines"][0]) <= 1 for x in matches),
                      f"got {[x['line'] for x in matches]}")
                check(f"{ann['sample_id']} 类别=={ann['category']}",
                      all(x["category"] == ann["category"] for x in matches))


def t2_negatives(tmp):
    print("T2 全量 negative 靶场：无匹配 finding")
    for cat in ["A01", "A02", "A03", "A04", "A05"]:
        base = CORPUS / cat / "negative"
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            ann = json.loads((d / "annotation.json").read_text(encoding="utf-8"))
            code = corpus_code(d)
            r = repo(tmp, f"n-{ann['sample_id']}")
            (r / code[0].name).write_bytes(code[0].read_bytes())
            try:
                finding = pipeline(r, {})
            except subprocess.CalledProcessError:
                check(f"{ann['sample_id']} 管线可跑", False)
                continue
            leaks = [x for x in finding["findings"] if x["pattern"] == ann["pattern"]]
            check(f"{ann['sample_id']} 无 {ann['pattern']} finding", not leaks,
                  f"leaked {[(x['pattern'], x['line']) for x in leaks]}")


# ---------------------------------------------------------------------------
# T3：judge_scripted 决策
# ---------------------------------------------------------------------------

def _it(rid, evidence):
    return {"review_id": rid, "candidate_id": rid, "pattern": "sql_concat", "cwe": "CWE-89",
            "fix_hint": "参数化", "evidence": evidence}


def t3_scripted():
    print("T3 judge_scripted：接收器+无缓解 → confirm；缓解/无接收器 → reject")
    a = judge_scripted(_it("c1", [{"kind": "sink", "value": "cur.execute(f'...{x}')"},
                                  {"kind": "user_controlled", "value": "request.form"}]))
    check("sink+user_controlled → confirm", a["verdict"] == "confirm", f"got {a}")
    b = judge_scripted(_it("c2", [{"kind": "sink", "value": "q"}, {"kind": "sanitizer", "value": "parameterized"}]))
    check("sanitizer=parameterized → reject", b["verdict"] == "reject", f"got {b}")
    c = judge_scripted(_it("c3", [{"kind": "auth", "value": "guard"}]))
    check("auth=guard → reject", c["verdict"] == "reject", f"got {c}")
    d = judge_scripted(_it("c4", []))
    check("无接收器 → reject", d["verdict"] == "reject", f"got {d}")
    e = judge_scripted(_it("c5", [{"kind": "sink", "value": "s"}, {"kind": "sanitizer", "value": "none"}]))
    check("sanitizer=none → confirm", e["verdict"] == "confirm", f"got {e}")


# ---------------------------------------------------------------------------
# T4：build_pack 预算分批
# ---------------------------------------------------------------------------

def _synth_review_plan(rids):
    return {"meta": {"source_candidate": "candidate.json"}, "findings_static": [],
            "decisions": [], "review_ids": rids}


def _synth_candidate(rid, i, ctx_size):
    return {"candidate_id": rid, "category": "A05", "pattern": "sql_concat",
            "file": f"app{i}.py", "line": 10 + i, "confidence": "high",
            "evidence": [{"kind": "sink", "value": "cur.execute(query)"}],
            "context": "payload " * ctx_size}


def t4_budget():
    print("T4 build_pack：超预算自动分批 + 单条超限显式记录")
    reg = load_registry()
    rids = [f"R-{i:03d}" for i in range(30)]
    cand = {"candidates": [_synth_candidate(r, i, 300) for i, r in enumerate(rids)]}
    pack = build_pack(_synth_review_plan(rids), cand, reg, budget=12000)
    check("30 条大窗口候选分批 > 1", pack["meta"]["batch_count"] > 1,
          f"got {pack['meta']['batch_count']}")
    check("整包估算超预算被标记", pack["meta"]["within_budget"] is False,
          f"tokens={pack['meta']['estimated_prompt_tokens']}")
    check("每批估算 token 在预算内", all(
        estimate_tokens(json.dumps(b, ensure_ascii=False)) <= 12000 for b in pack["batches"]))

    big_rid = "R-HUGE"
    pack2 = build_pack(_synth_review_plan([big_rid]),
                       {"candidates": [_synth_candidate(big_rid, 99, 40000)]},
                       reg, budget=12000)
    check("单条超限进 oversized 而不被丢弃", big_rid in pack2["meta"]["oversized"],
          f"got {pack2['meta']['oversized']}")
    check("单条超限仍独立成批（R7 不静默截断）", pack2["meta"]["batch_count"] == 1)

    pack3 = build_pack(_synth_review_plan([]), {"candidates": []}, reg, budget=12000)
    check("空 review（全静态）打包正常", pack3["meta"]["review_count"] == 0
          and pack3["meta"]["batch_count"] == 0)


# ---------------------------------------------------------------------------
# T5：脱敏贯通
# ---------------------------------------------------------------------------

def t5_redaction(tmp):
    print("T5 脱敏贯通：密钥原文不进 finding.json")
    d = CORPUS / "A04" / "positive" / "A04-secret-001"
    r = repo(tmp, "t5-secret")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    finding = pipeline(r, {})
    raw = "sk-test-1234567890abcdef"
    matches = [x for x in finding["findings"] if x["pattern"] == "hardcoded_secret"]
    check("hardcoded_secret 静态 finding 存在", bool(matches))
    blob = json.dumps(finding, ensure_ascii=False)
    check("密钥原文不在 finding.json", raw not in blob)
    check("finding evidence 已掩码", matches and any("***" in e["value"] for e in matches[0]["evidence"]))


# ---------------------------------------------------------------------------
# T6：契约 / 空 review / CLI --answers 接线
# ---------------------------------------------------------------------------

def t6_contract(tmp):
    print("T6 契约：字段 / verdict / 计数闭合 / rejected / 空 review / CLI 接线")
    # A01-idor-001 → reviewer 确认（CONFIRMED_BY_REVIEWER）
    d = CORPUS / "A01" / "positive" / "A01-idor-001"
    r = repo(tmp, "t6-idor")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    finding = pipeline(r, {})
    ids = set()
    for f in finding["findings"]:
        ids.add(f["finding_id"])
        check("finding 字段齐全",
              {"finding_id", "candidate_id", "category", "pattern", "cwe", "file", "line",
               "severity", "verdict", "confidence", "evidence", "context"}.issubset(f.keys()))
        check("verdict 合法", f["verdict"] in {"CONFIRMED_BY_RULE", "CONFIRMED_BY_REVIEWER",
                                                "CONFIRMED", "REJECT", "ESCALATE"})
        check("severity 合法", f["severity"] in {"high", "medium", "low"})
        check("cwe 非空", bool(f["cwe"]))
    check("idor-001 为 CONFIRMED_BY_REVIEWER",
          any(x["pattern"] == "idor_missing_scope_check" and x["verdict"] == "CONFIRMED_BY_REVIEWER"
              for x in finding["findings"]))
    check("finding_id 唯一", len(ids) == len(finding["findings"]))
    c = finding["meta"]["counts"]
    check("计数闭合", c["total"] == c["static"] + c["reviewer_confirm"]
          and c["rejected_total"] == c["reviewer_reject"], f"got {c}")
    check("review_budget 字段齐全",
          {"max_tokens", "estimated_prompt_tokens", "batch_count", "within_budget"}
          .issubset(finding["meta"]["review_budget"].keys()))

    # A02-debug-001 → 全静态，review 为空
    d = CORPUS / "A02" / "positive" / "A02-debug-001"
    r = repo(tmp, "t6-debug")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    finding = pipeline(r, {})
    c = finding["meta"]["counts"]
    check("debug 样本全静态结案", c["reviewer_confirm"] == 0 and c["static"] >= 1, f"got {c}")
    check("debug finding 为 CONFIRMED_BY_RULE",
          all(x["verdict"] == "CONFIRMED_BY_RULE" for x in finding["findings"]))
    check("debug 样本 rejected 为空", finding["rejected"] == [])

    # CLI --answers 接线：A05-sql-001
    d = CORPUS / "A05" / "positive" / "A05-sql-001"
    r = repo(tmp, "t6-answers")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    subprocess.run([sys.executable, str(COLLECTOR), "-o", "change.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(ANALYZER), "-i", "change.json", "-o", "impact_map.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(SIGNAL), "-c", "change.json",
                    "-m", "impact_map.json", "-o", "candidate.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(ROUTER), "-c", "candidate.json", "-o", "review_plan.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(REVIEWER), "build", "-r", "review_plan.json",
                    "-c", "candidate.json", "-o", "review_pack.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    pack = json.loads((r / "review_pack.json").read_text(encoding="utf-8"))
    check("review_pack 含 sql_concat 候选", any(
        it["pattern"] == "sql_concat" for b in pack["batches"] for it in b))
    rid = next(it["review_id"] for b in pack["batches"] for it in b if it["pattern"] == "sql_concat")
    answers = {"meta": {"source_review_pack": "review_pack.json", "answered": 1},
               "answers": [{"review_id": rid, "verdict": "confirm", "cwe": "CWE-89",
                            "severity": "high", "reason": "插值拼接用户输入",
                            "fix_hint": "参数化"}]}
    (r / "review_answers.json").write_text(json.dumps(answers), encoding="utf-8")
    subprocess.run([sys.executable, str(REVIEWER), "review", "-r", "review_plan.json",
                    "-c", "candidate.json", "--answers", "review_answers.json",
                    "-o", "finding.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    finding = json.loads((r / "finding.json").read_text(encoding="utf-8"))
    check("CLI --answers 产出 sql finding",
          any(x["pattern"] == "sql_concat" and x["verdict"] == "CONFIRMED_BY_REVIEWER"
              for x in finding["findings"]))


# ---------------------------------------------------------------------------
# T7：finalize 校验
# ---------------------------------------------------------------------------

def t7_validation():
    print("T7 finalize 校验：缺答/重复/未知 id/非法 verdict → ValueError")
    reg = load_registry()
    rid = "R-1"
    cand = {"candidates": [_synth_candidate(rid, 1, 5)]}
    pack = build_pack(_synth_review_plan([rid]), cand, reg, budget=12000)

    def expect_err(name, answers):
        try:
            finalize(_synth_review_plan([rid]), pack, answers)
            check(name, False, "未抛错")
        except ValueError:
            check(name, True)

    expect_err("缺答 → ValueError", [])
    expect_err("未知 review_id → ValueError",
               [{"review_id": "R-X", "verdict": "confirm", "cwe": "CWE-89", "severity": "high"}])
    expect_err("重复 answer → ValueError",
               [{"review_id": rid, "verdict": "confirm", "cwe": "CWE-89", "severity": "high"}] * 2)
    expect_err("非法 verdict → ValueError",
               [{"review_id": rid, "verdict": "maybe"}])
    expect_err("confirm 缺 severity → ValueError",
               [{"review_id": rid, "verdict": "confirm", "cwe": "CWE-89"}])

    good = [{"review_id": rid, "verdict": "reject", "reason": "字面量无输入"}]
    finding = finalize(_synth_review_plan([rid]), pack, good)
    check("reject 进 rejected 附录", finding["rejected"] and finding["rejected"][0]["review_id"] == rid)
    check("reject 不产 finding", finding["findings"] == [])


def main():
    tmp = Path(tempfile.mkdtemp(prefix="m6_reviewer_"))
    try:
        t1_positives(tmp)
        t2_negatives(tmp)
        t3_scripted()
        t4_budget()
        t5_redaction(tmp)
        t6_contract(tmp)
        t7_validation()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total, failed = len(_results), _results.count(False)
    print(f"\n== {total - failed}/{total} 通过 ==")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
