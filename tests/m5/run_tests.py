#!/usr/bin/env python3
"""
M5 Risk Router 验收测试（无第三方依赖，仅 git + python3）。

用法: python tests/m5/run_tests.py
覆盖:
  T1 全量 positive 靶场：15 样本的匹配候选都被路由到 {finding, review}（不漏检）
  T2 全量 negative 靶场：无匹配候选进入 {finding, review}（不误报）
  T3 decide() 决策表：确定性规则 high → finding
  T4 decide() 决策表：缺位/低置信 → skip；sanitizer/鉴权 evidence → clean
  T5 decide() 决策表：语义类 → review
  T6 计数闭合：total = finding+review+skip+clean
  T7 契约：decisions/review_ids/findings_static 字段齐全
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
CORPUS = ROOT / "code-review" / "tests"

sys.path.insert(0, str(WORKFLOW))
from router import ROUTE_FINDING, ROUTE_SKIP, decide  # noqa: E402

_results: list[bool] = []


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


def init_repo(cwd):
    git(cwd, "init", "-q")
    git(cwd, "config", "user.email", "m5@test")
    git(cwd, "config", "user.name", "M5Test")


def pipeline(cwd, files: dict[str, str]):
    for name, content in files.items():
        (cwd / name).write_text(content, encoding="utf-8")
    subprocess.run([sys.executable, str(COLLECTOR), "-o", "change.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(ANALYZER), "-i", "change.json", "-o", "impact_map.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(SIGNAL), "-c", "change.json",
                    "-m", "impact_map.json", "-o", "candidate.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(ROUTER), "-c", "candidate.json", "-o", "review_plan.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    return json.loads((cwd / "review_plan.json").read_text(encoding="utf-8"))


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


def t1_positives(tmp):
    print("T1 positive 靶场：匹配候选进入 {finding, review}")
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
                plan = pipeline(r, {})
            except subprocess.CalledProcessError:
                check(f"{ann['sample_id']} 管线可跑", False)
                continue
            rows = [x for x in plan["decisions"] if x["pattern"] == ann["pattern"]]
            check(f"{ann['sample_id']} 匹配候选被路由",
                  bool(rows) and all(x["decision"] in {"finding", "review"} for x in rows),
                  f"got {[(x['pattern'], x['decision']) for x in plan['decisions']]}")


def t2_negatives(tmp):
    print("T2 negative 靶场：无匹配候选进入 {finding, review}")
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
                plan = pipeline(r, {})
            except subprocess.CalledProcessError:
                check(f"{ann['sample_id']} 管线可跑", False)
                continue
            bad = [x for x in plan["decisions"]
                   if x["pattern"] == ann["pattern"] and x["decision"] in {"finding", "review"}]
            check(f"{ann['sample_id']} 不误报 {ann['pattern']}", not bad,
                  f"got {[(x['pattern'], x['decision']) for x in plan['decisions']]}")


def t3_finding_table():
    print("T3 decide：确定性规则 high → finding")
    for pat in ["hardcoded_secret", "permissive_cors", "debug_enabled",
                "default_credentials", "unpinned_dependency"]:
        c = {"pattern": pat, "confidence": "high", "evidence": [{"kind": "sink", "value": "x"}]}
        dec, _ = decide(c)
        check(f"{pat} high → finding", dec == "finding", f"got {dec}")


def t4_skip_clean_table():
    print("T4 decide：缺位/低置信 → skip；有防护 → clean")
    for pat in ROUTE_SKIP:
        c = {"pattern": pat, "confidence": "low", "evidence": []}
        dec, _ = decide(c)
        check(f"{pat} → skip", dec == "skip", f"got {dec}")
    c = {"pattern": "sql_concat", "confidence": "low", "evidence": [{"kind": "sink", "value": "x"}]}
    dec, _ = decide(c)
    check("sql_concat low（变量参数）→ skip", dec == "skip", f"got {dec}")
    c = {"pattern": "sql_concat", "confidence": "high",
         "evidence": [{"kind": "sink", "value": "x"}, {"kind": "sanitizer", "value": "parameterized"}]}
    dec, _ = decide(c)
    check("sanitizer evidence → clean", dec == "clean", f"got {dec}")
    c = {"pattern": "ssrf_user_url", "confidence": "high",
         "evidence": [{"kind": "auth", "value": "guard"}]}
    dec, _ = decide(c)
    check("auth evidence → clean", dec == "clean", f"got {dec}")


def t5_review_table():
    print("T5 decide：语义类 → review")
    for pat, conf in [("sql_concat", "high"), ("command_concat", "high"),
                      ("eval_injection", "high"), ("xss_innerHTML", "medium"),
                      ("idor_missing_scope_check", "medium"), ("ssrf_user_url", "medium"),
                      ("weak_crypto", "high"), ("weak_rng", "medium")]:
        c = {"pattern": pat, "confidence": conf,
             "evidence": [{"kind": "sink", "value": "x"}, {"kind": "sanitizer", "value": "none"}]}
        dec, _ = decide(c)
        check(f"{pat} {conf} → review", dec == "review", f"got {dec}")


def t6_counts(tmp):
    print("T6 计数闭合：total = finding+review+skip+clean")
    d = CORPUS / "A01" / "positive" / "A01-idor-001"
    r = repo(tmp, "t6-counts")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    plan = pipeline(r, {})
    c = plan["meta"]["counts"]
    check("total 闭合", c["total"] == c["finding"] + c["review"] + c["skip"] + c["clean"],
          f"got {c}")
    check("review_ids 与 decisions 一致",
          set(plan["review_ids"]) == {x["candidate_id"] for x in plan["decisions"] if x["decision"] == "review"})


def t7_contract(tmp):
    print("T7 契约：decisions / findings_static / review_ids 字段")
    d = CORPUS / "A02" / "positive" / "A02-debug-001"
    r = repo(tmp, "t7-contract")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    plan = pipeline(r, {})
    for x in plan["decisions"]:
        check("decision 字段齐全",
              {"candidate_id", "pattern", "category", "file", "line", "confidence",
               "decision", "reason"}.issubset(x.keys()))
        check("decision 枚举", x["decision"] in {"finding", "review", "skip", "clean"})
    fs = plan["findings_static"]
    check("debug_enabled 静态结案为 finding", any(x["pattern"] == "debug_enabled" for x in fs))
    if fs:
        f = fs[0]
        check("finding 字段齐全",
              {"finding_id", "candidate_id", "category", "pattern", "cwe", "file", "line",
               "severity", "verdict", "evidence", "context"}.issubset(f.keys()))
        check("verdict==CONFIRMED_BY_RULE", f["verdict"] == "CONFIRMED_BY_RULE")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="m5_router_"))
    try:
        t1_positives(tmp)
        t2_negatives(tmp)
        t3_finding_table()
        t4_skip_clean_table()
        t5_review_table()
        t6_counts(tmp)
        t7_contract(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total, failed = len(_results), _results.count(False)
    print(f"\n== {total - failed}/{total} 通过 ==")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
