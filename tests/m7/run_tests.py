#!/usr/bin/env python3
"""
M7 Verifier + Dedup 验收测试（无第三方依赖，仅 git + python3）。

用法: python tests/m7/run_tests.py
逐项构建临时 git 仓库 → collect → analyze → signal → router → reviewer（--scripted）
→ verifier verify（--scripted）→ dedup。
覆盖:
  T1 全量 positive 靶场：15 样本经 对抗复核+去重 后仍产出匹配 finding（verdict∈{CONFIRMED,ESCALATE}）
  T2 全量 negative 靶场：无匹配 pattern 的 finding
  T3 verify_scripted 三态：已缓解/无锚点 → reject；中等置信 → escalate；否则 confirm
  T4 build 预算分批：超预算自动分批、单条超限显式记录（R7 不静默截断）
  T5 脱敏贯通：hardcoded_secret 密钥原文经复核+去重仍不进最终文档
  T6 契约：三态 verdict / origin_verdict 保留 / rejected stage / 计数闭合 / 预算字段
  T7 dedup：同 (file,cwe) 相邻合并、异 cwe/远行不合并、ESCALATE 优先、line_span 并集、计数
  T8 apply_verdicts 校验：缺答/重复/未知 id/非法 verdict → ValueError
  T9 CLI 接线：build → 手写 verification_answers.json → verify --answers → dedup
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
VERIFIER = WORKFLOW / "verifier.py"
CORPUS = ROOT / "code-review" / "tests"

sys.path.insert(0, str(WORKFLOW))
from reviewer import estimate_tokens  # noqa: E402
from verifier import (apply_verdicts, build_verification_pack, dedup_doc,  # noqa: E402
                      dedup_findings, load_registry, verify_scripted)

_results: list[bool] = []


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


def init_repo(cwd):
    git(cwd, "init", "-q")
    git(cwd, "config", "user.email", "m7@test")
    git(cwd, "config", "user.name", "M7Test")


def pipeline(cwd, files: dict[str, str]):
    """collect → analyze → signal → router → reviewer --scripted → verifier --scripted → dedup，
    返回终态 finding.json。"""
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
    subprocess.run([sys.executable, str(REVIEWER), "review", "-r", "review_plan.json",
                    "-c", "candidate.json", "-o", "finding.json", "--scripted"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(VERIFIER), "verify", "-i", "finding.json",
                    "-o", "finding.json", "--scripted"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(VERIFIER), "dedup", "-i", "finding.json",
                    "-o", "finding.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
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
# 合成 finding 文档/条目
# ---------------------------------------------------------------------------

def synth_finding(fid, line, file="app.py", cwe="CWE-89", pattern="sql_concat",
                  category="A05", severity="high", confidence="high",
                  verdict="CONFIRMED_BY_REVIEWER", context="", evidence=None,
                  line_span=None):
    return {
        "finding_id": fid, "candidate_id": fid, "category": category,
        "pattern": pattern, "cwe": cwe, "file": file, "line": line,
        "severity": severity, "verdict": verdict, "confidence": confidence,
        "evidence": evidence if evidence is not None else [{"kind": "sink", "value": f"sink(line {line})"}],
        "context": context or "payload " * 5,
        "line_span": line_span or [line, line],
    }


def synth_finding_doc(fs):
    return {
        "meta": {"source_review_plan": "rp", "source_review_pack": "rp",
                 "generated_at": "t", "counts": {"total": len(fs), "static": 0,
                 "reviewer_confirm": len(fs), "reviewer_reject": 0, "rejected_total": 0},
                 "review_budget": {"max_tokens": 12000, "estimated_prompt_tokens": 0,
                                   "batch_count": 1, "within_budget": True}},
        "findings": fs, "rejected": [],
    }


def _verdicts(doc):
    return {x["finding_id"]: x["verdict"] for x in doc["findings"]}


# ---------------------------------------------------------------------------
# T1 / T2：全量靶场贯通
# ---------------------------------------------------------------------------

# A03/A06 重叠注记（design-locked §6）：unpinned_dependency(A03, CWE-1104) 与
# floating_dependency(A06, CWE-1104) 描述同一缺陷；浮动版本行两规则都会触发，
# dedup 按 (file, cwe) 合并为一条，保留排序靠前的 A03 命名。因此 A06 floating
# 正例在 m7 阶段按「同族 + 行号」验收——精确 pattern 已在 m4/m6 阶段验证。
FAMILY = {
    "floating_dependency": {"floating_dependency", "unpinned_dependency"},
    "unpinned_dependency": {"unpinned_dependency", "floating_dependency"},
}


def t1_positives(tmp):
    print("T1 全量 positive 靶场：复核+去重后仍产出匹配 finding（verdict∈{CONFIRMED,ESCALATE}）")
    for cat in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
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
            fam = FAMILY.get(ann["pattern"], {ann["pattern"]})
            matches = [x for x in fs if x["pattern"] in fam]
            check(f"{ann['sample_id']} 产出 {ann['pattern']} 同族 finding",
                  bool(matches), f"got {[x['pattern'] for x in fs]}")
            if matches:
                check(f"{ann['sample_id']} verdict 为 CONFIRMED/ESCALATE",
                      all(x["verdict"] in ("CONFIRMED", "ESCALATE") for x in matches),
                      f"got {[x['verdict'] for x in matches]}")
                check(f"{ann['sample_id']} 行号±1（标注 {ann['lines']}）",
                      any(abs(x["line"] - ann["lines"][0]) <= 1 for x in matches),
                      f"got {[x['line'] for x in matches]}")
                check(f"{ann['sample_id']} 类别在标注族内",
                      all(x["category"] in {ann["category"]} or
                          (ann["pattern"] in FAMILY and x["category"] in {"A03", "A06"})
                          for x in matches))


def t2_negatives(tmp):
    print("T2 全量 negative 靶场：无匹配 finding")
    for cat in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
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
# T3：verify_scripted 三态
# ---------------------------------------------------------------------------

def _it(fid, evidence, conf="high"):
    return {"finding_id": fid, "confidence": conf, "evidence": evidence}


def t3_scripted():
    print("T3 verify_scripted：已缓解/无锚点→reject；中等置信→escalate；否则 confirm")
    a = verify_scripted(_it("f1", [{"kind": "sink", "value": "s"}, {"kind": "sanitizer", "value": "parameterized"}]))
    check("sanitizer 存在 → reject", a["verdict"] == "reject", f"got {a}")
    b = verify_scripted(_it("f2", [{"kind": "sink", "value": "s"}, {"kind": "auth", "value": "guard"}]))
    check("auth 存在 → reject", b["verdict"] == "reject", f"got {b}")
    c = verify_scripted(_it("f3", [{"kind": "foo", "value": "bar"}]))
    check("无锚点 → reject", c["verdict"] == "reject", f"got {c}")
    d = verify_scripted(_it("f4", [{"kind": "sink", "value": "s"}], conf="medium"))
    check("中等置信 → escalate", d["verdict"] == "escalate", f"got {d}")
    e = verify_scripted(_it("f5", [{"kind": "sink", "value": "s"}]))
    check("高置信+锚点 → confirm", e["verdict"] == "confirm", f"got {e}")
    f = verify_scripted(_it("f6", [{"kind": "config", "value": "debug=True"}]))
    check("config 锚点（debug）→ confirm", f["verdict"] == "confirm", f"got {f}")


# ---------------------------------------------------------------------------
# T4：build 预算分批
# ---------------------------------------------------------------------------

def t4_budget():
    print("T4 build_verification_pack：超预算自动分批 + 单条超限显式记录")
    fs = [synth_finding(f"F-{i:03d}", 10 + i, context="payload " * 200) for i in range(30)]
    pack = build_verification_pack(synth_finding_doc(fs), load_registry(), budget=5000)
    check("30 条大窗口 finding 分批 > 1", pack["meta"]["batch_count"] > 1,
          f"got {pack['meta']['batch_count']}")
    check("整包超预算被标记", pack["meta"]["within_budget"] is False,
          f"tokens={pack['meta']['estimated_prompt_tokens']}")
    check("每批估算 token 在预算内", all(
        estimate_tokens(json.dumps(b, ensure_ascii=False)) <= 5000 for b in pack["batches"]))

    big = synth_finding("F-HUGE", 1, context="payload " * 40000)
    pack2 = build_verification_pack(synth_finding_doc([big]), load_registry(), budget=5000)
    check("单条超限进 oversized 而不被丢弃", "F-HUGE" in pack2["meta"]["oversized"],
          f"got {pack2['meta']['oversized']}")
    check("单条超限仍独立成批（R7 不静默截断）", pack2["meta"]["batch_count"] == 1)

    pack3 = build_verification_pack(synth_finding_doc([]), load_registry(), budget=5000)
    check("空 finding（全被拒）打包正常", pack3["meta"]["verification_count"] == 0
          and pack3["meta"]["batch_count"] == 0)


# ---------------------------------------------------------------------------
# T5：脱敏贯通
# ---------------------------------------------------------------------------

def t5_redaction(tmp):
    print("T5 脱敏贯通：密钥原文经复核+去重仍不进最终文档")
    d = CORPUS / "A04" / "positive" / "A04-secret-001"
    r = repo(tmp, "t5-secret")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    finding = pipeline(r, {})
    raw = "sk-test-1234567890abcdef"
    matches = [x for x in finding["findings"] if x["pattern"] == "hardcoded_secret"]
    check("hardcoded_secret finding 存在", bool(matches))
    check("verdict 为 CONFIRMED（静态高置信）",
          matches and matches[0]["verdict"] == "CONFIRMED", f"got {[x['verdict'] for x in matches]}")
    blob = json.dumps(finding, ensure_ascii=False)
    check("密钥原文不在最终文档", raw not in blob)
    check("finding evidence 已掩码", matches and any("***" in e["value"] for e in matches[0]["evidence"]))


# ---------------------------------------------------------------------------
# T6：契约
# ---------------------------------------------------------------------------

def t6_contract(tmp):
    print("T6 契约：三态 verdict / origin_verdict / rejected stage / 计数闭合 / 预算字段")

    # A01-idor-001：medium 置信 → ESCALATE，origin=CONFIRMED_BY_REVIEWER
    d = CORPUS / "A01" / "positive" / "A01-idor-001"
    r = repo(tmp, "t6-idor")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    finding = pipeline(r, {})
    idor = [x for x in finding["findings"] if x["pattern"] == "idor_missing_scope_check"]
    check("idor-001 → ESCALATE（中等置信）",
          idor and idor[0]["verdict"] == "ESCALATE", f"got {[x['verdict'] for x in idor]}")
    check("origin_verdict 保留 CONFIRMED_BY_REVIEWER",
          idor and idor[0]["origin_verdict"] == "CONFIRMED_BY_REVIEWER",
          f"got {[x.get('origin_verdict') for x in idor]}")
    check("line_span 存在且覆盖锚点行",
          idor and idor[0]["line_span"][0] <= idor[0]["line"] <= idor[0]["line_span"][1])
    c = finding["meta"]["counts"]
    check("计数闭合 total==confirmed+escalated",
          c["total"] == c["confirmed"] + c["escalated"], f"got {c}")
    check("verification_budget 字段齐全",
          {"max_tokens", "estimated_prompt_tokens", "batch_count", "within_budget"}
          .issubset(finding["meta"]["verification_budget"].keys()))

    # A05-sql-001：high 置信 → CONFIRMED
    d = CORPUS / "A05" / "positive" / "A05-sql-001"
    r = repo(tmp, "t6-sql")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    finding = pipeline(r, {})
    sql = [x for x in finding["findings"] if x["pattern"] == "sql_concat"]
    check("sql-001 → CONFIRMED（高置信）",
          sql and sql[0]["verdict"] == "CONFIRMED", f"got {[x['verdict'] for x in sql]}")

    # A02-debug-001：静态结案 finding 复核后 origin=CONFIRMED_BY_RULE
    d = CORPUS / "A02" / "positive" / "A02-debug-001"
    r = repo(tmp, "t6-debug")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    finding = pipeline(r, {})
    dbg = [x for x in finding["findings"] if x["pattern"] == "debug_enabled"]
    check("debug-001 静态 finding 复核后 CONFIRMED + origin=CONFIRMED_BY_RULE",
          dbg and dbg[0]["verdict"] == "CONFIRMED"
          and dbg[0]["origin_verdict"] == "CONFIRMED_BY_RULE",
          f"got {[(x['verdict'], x.get('origin_verdict')) for x in dbg]}")

    # 直接构造：verify_scripted 判 reject 的 finding 应进 rejected 附录（stage=verifier）
    fs = [synth_finding("F-RJ", 1, evidence=[{"kind": "sink", "value": "s"},
                                             {"kind": "sanitizer", "value": "parameterized"}])]
    doc = synth_finding_doc(fs)
    pack = build_verification_pack(doc, load_registry(), budget=5000)
    answers = [verify_scripted(pack["batches"][0][0])]
    verified = apply_verdicts(doc, pack, answers)
    check("verifier REJECT 移出 findings", verified["findings"] == [])
    rj = [x for x in verified["rejected"] if x.get("stage") == "verifier"]
    check("REJECT 进 rejected 附录且 stage=verifier",
          rj and rj[0]["verdict"] == "REJECT" and rj[0]["finding_id"] == "F-RJ",
          f"got {[x.get('finding_id') for x in rj]}")
    check("rejected_by_verifier 计数==1", verified["meta"]["counts"]["rejected_by_verifier"] == 1)


# ---------------------------------------------------------------------------
# T7：dedup
# ---------------------------------------------------------------------------

def t7_dedup():
    print("T7 dedup：(file,cwe) 相邻合并 / 异类不合并 / ESCALATE 优先 / line_span 并集")
    fs = [
        synth_finding("F-1", 10),
        synth_finding("F-2", 11),                       # 相邻 → 与 F-1 合并
        synth_finding("F-3", 10, cwe="CWE-79", pattern="xss_innerHTML"),  # 异 cwe 不合并
        synth_finding("F-4", 50),                       # 远行不合并
        synth_finding("F-5", 12, confidence="medium", severity="low",
                      verdict="CONFIRMED_BY_REVIEWER"),  # 与合并体相邻 → 并入 F-1+F-2
    ]
    out, merged = dedup_findings(fs)
    check("同 (file,cwe) 相邻合并", merged == 2, f"merged={merged}")
    by_id = {x["finding_id"]: x for x in out}
    check("F-1+F-2 合并为一条", "F-1" in by_id and "F-2" not in by_id, f"got {list(by_id)}")
    f1 = by_id["F-1"]
    check("合并 span 覆盖 [10,12]", f1["line_span"] == [10, 12], f"got {f1['line_span']}")
    check("合并 line 取 span 起点", f1["line"] == 10)
    check("合并保留更高严重度（F-5 low 被高覆盖）", f1["severity"] == "high", f"got {f1['severity']}")
    check("异 cwe 保持独立", "F-3" in by_id)
    check("远行保持独立", "F-4" in by_id)
    check("合并条目证据去重且保留全部", len(f1["evidence"]) >= 1)

    # ESCALATE + CONFIRMED 合并 → ESCALATE
    es = [synth_finding("F-E1", 20, verdict="CONFIRMED_BY_REVIEWER", confidence="high"),
          synth_finding("F-E2", 21, verdict="CONFIRMED_BY_REVIEWER", confidence="medium")]
    es[1]["verdict"] = "ESCALATE"
    out2, _ = dedup_findings(es)
    check("合并含 ESCALATE → 结果 ESCALATE", out2[0]["verdict"] == "ESCALATE",
          f"got {out2[0]['verdict']}")

    # dedup_doc 计数更新
    doc = synth_finding_doc(fs)
    final = dedup_doc(doc)
    check("dedup_doc 更新 total/dedup_merged", final["meta"]["counts"]["total"] == len(final["findings"])
          and final["meta"]["counts"]["dedup_merged"] == merged,
          f"got {final['meta']['counts']}")


# ---------------------------------------------------------------------------
# T8：apply_verdicts 校验
# ---------------------------------------------------------------------------

def t8_validation():
    print("T8 apply_verdicts 校验：缺答/重复/未知 id/非法 verdict → ValueError")
    doc = synth_finding_doc([synth_finding("F-1", 1)])
    pack = build_verification_pack(doc, load_registry(), budget=5000)

    def expect_err(name, answers):
        try:
            apply_verdicts(doc, pack, answers)
            check(name, False, "未抛错")
        except ValueError:
            check(name, True)

    expect_err("缺答 → ValueError", [])
    expect_err("未知 finding_id → ValueError", [{"finding_id": "F-X", "verdict": "confirm", "reason": "r"}])
    expect_err("重复 answer → ValueError",
               [{"finding_id": "F-1", "verdict": "confirm", "reason": "r"}] * 2)
    expect_err("非法 verdict → ValueError", [{"finding_id": "F-1", "verdict": "maybe"}])

    good = [{"finding_id": "F-1", "verdict": "reject", "reason": "假阳性"}]
    verified = apply_verdicts(doc, pack, good)
    check("reject 进 rejected 附录", verified["rejected"] and verified["rejected"][0]["finding_id"] == "F-1")
    check("reject 不产 finding", verified["findings"] == [])


# ---------------------------------------------------------------------------
# T9：CLI 接线（build → answers → verify --answers → dedup）
# ---------------------------------------------------------------------------

def t9_cli(tmp):
    print("T9 CLI 接线：build → 手写 answers → verify --answers → dedup")
    d = CORPUS / "A05" / "positive" / "A05-sql-001"
    r = repo(tmp, "t9-cli")
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
    subprocess.run([sys.executable, str(REVIEWER), "review", "-r", "review_plan.json",
                    "-c", "candidate.json", "-o", "finding.json", "--scripted"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(VERIFIER), "build", "-i", "finding.json",
                    "-o", "verification_pack.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    pack = json.loads((r / "verification_pack.json").read_text(encoding="utf-8"))
    check("verification_pack 含 sql_concat finding", any(
        it["pattern"] == "sql_concat" for b in pack["batches"] for it in b))
    fid = next(it["finding_id"] for b in pack["batches"] for it in b if it["pattern"] == "sql_concat")
    answers = {"meta": {"source_verification_pack": "verification_pack.json", "answered": 1},
               "answers": [{"finding_id": fid, "verdict": "confirm",
                            "reason": "对抗复核：插值拼接用户输入可达 execute，无缓解",
                            "cwe": "CWE-89", "severity": "high"}]}
    (r / "verification_answers.json").write_text(json.dumps(answers), encoding="utf-8")
    subprocess.run([sys.executable, str(VERIFIER), "verify", "-i", "finding.json",
                    "--answers", "verification_answers.json", "-o", "verified.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(VERIFIER), "dedup", "-i", "verified.json",
                    "-o", "finding_final.json"],
                   cwd=str(r), check=True, capture_output=True, text=True)
    final = json.loads((r / "finding_final.json").read_text(encoding="utf-8"))
    sql = [x for x in final["findings"] if x["pattern"] == "sql_concat"]
    check("CLI --answers 产出 CONFIRMED sql finding（含 cwe/severity 覆盖）",
          sql and sql[0]["verdict"] == "CONFIRMED" and sql[0]["cwe"] == "CWE-89"
          and sql[0]["severity"] == "high", f"got {[x.get('verdict') for x in sql]}")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="m7_verifier_"))
    try:
        t1_positives(tmp)
        t2_negatives(tmp)
        t3_scripted()
        t4_budget()
        t5_redaction(tmp)
        t6_contract(tmp)
        t7_dedup()
        t8_validation()
        t9_cli(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total, failed = len(_results), _results.count(False)
    print(f"\n== {total - failed}/{total} 通过 ==")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
