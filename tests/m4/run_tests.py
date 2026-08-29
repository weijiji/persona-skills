#!/usr/bin/env python3
"""
M4 Signal Engine 验收测试（无第三方依赖，仅 git + python3）。

用法: python tests/m4/run_tests.py
逐项构建临时 git 仓库 → collect.py → analyze.py → signal_engine.py → 断言 candidate.json。
覆盖:
  T1 全量 positive 靶场：15 样本各产出 pattern 匹配、行号±1 的候选
  T2 全量 negative 靶场：10 样本不产出同名候选
  T3 脱敏：hardcoded_secret 候选的 evidence/context 不含密钥原文
  T4 变更行锚定：所有候选行必须落在 diff 新增行上
  T5 无靶场规则的合成夹具：handler_without_auth / csrf / xxe / missing_lockfile /
     untrusted_registry / xss_innerHTML 各 1 正 1 负
  T6 registry 18 条规则全部有检测器
  T7 候选契约：字段齐全、confidence 枚举、evidence kind 枚举、candidate_id 唯一
"""
import json
import os
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
CORPUS = ROOT / "code-review" / "tests"
REGISTRY = ROOT / "code-review" / "rules" / "registry.json"

sys.path.insert(0, str(WORKFLOW))
from gitutil import changed_lines_new  # noqa: E402
from signal_engine import DETECTORS  # noqa: E402

_results: list[bool] = []


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


def init_repo(cwd):
    git(cwd, "init", "-q")
    git(cwd, "config", "user.email", "m4@test")
    git(cwd, "config", "user.name", "M4Test")


def pipeline(cwd, files: dict[str, str]):
    """写文件（untracked）→ collect → analyze → signal → 返回 candidate.json。"""
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
    cand = json.loads((cwd / "candidate.json").read_text(encoding="utf-8"))
    change = json.loads((cwd / "change.json").read_text(encoding="utf-8"))
    return cand, change


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
    print("T1 全量 positive 靶场：每样本产对应候选 + 行号±1")
    for cat in ["A01", "A02", "A03", "A04", "A05"]:
        base = CORPUS / cat / "positive"
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            ann = json.loads((d / "annotation.json").read_text(encoding="utf-8"))
            code = corpus_code(d)
            if not code:
                check(f"{ann['sample_id']} 无代码文件", False)
                continue
            r = repo(tmp, ann["sample_id"])
            (r / code[0].name).write_bytes(code[0].read_bytes())
            try:
                cand, _ = pipeline(r, {})
            except subprocess.CalledProcessError:
                check(f"{ann['sample_id']} 管线可跑", False)
                continue
            matches = [c for c in cand["candidates"] if c["pattern"] == ann["pattern"]]
            check(f"{ann['sample_id']} 产出 {ann['pattern']} 候选",
                  bool(matches), f"got {[c['pattern'] for c in cand['candidates']]}")
            if matches:
                ok = any(abs(c["line"] - ann["lines"][0]) <= 1 for c in matches)
                check(f"{ann['sample_id']} 行号±1（标注 {ann['lines']}）",
                      ok, f"got {[c['line'] for c in matches]}")
                check(f"{ann['sample_id']} 类别=={ann['category']}",
                      all(c["category"] == ann["category"] for c in matches))


def t2_negatives(tmp):
    print("T2 全量 negative 靶场：不产出同名候选")
    for cat in ["A01", "A02", "A03", "A04", "A05"]:
        base = CORPUS / cat / "negative"
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            ann = json.loads((d / "annotation.json").read_text(encoding="utf-8"))
            code = corpus_code(d)
            if not code:
                check(f"{ann['sample_id']} 无代码文件", False)
                continue
            r = repo(tmp, ann["sample_id"])
            (r / code[0].name).write_bytes(code[0].read_bytes())
            try:
                cand, _ = pipeline(r, {})
            except subprocess.CalledProcessError:
                check(f"{ann['sample_id']} 管线可跑", False)
                continue
            leaks = [c for c in cand["candidates"] if c["pattern"] == ann["pattern"]]
            check(f"{ann['sample_id']} 无 {ann['pattern']} 候选", not leaks,
                  f"leaked {[(c['pattern'], c['line']) for c in leaks]}")


def t3_redaction(tmp):
    print("T3 脱敏：hardcoded_secret 密钥原文不进入 candidate.json")
    d = CORPUS / "A04" / "positive" / "A04-secret-001"
    r = repo(tmp, "t3-secret")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    cand, _ = pipeline(r, {})
    raw = "sk-test-1234567890abcdef"
    matches = [c for c in cand["candidates"] if c["pattern"] == "hardcoded_secret"]
    check("hardcoded_secret 候选存在", bool(matches))
    blob = json.dumps(cand, ensure_ascii=False)
    check("密钥原文不在 candidate.json", raw not in blob)
    check("evidence 值已被掩码", matches and any("***" in e["value"] for e in matches[0]["evidence"]))


def t4_changed_anchor(tmp):
    print("T4 变更行锚定：候选行必须是 diff 新增行")
    total = 0
    for cat in ["A01", "A02", "A03", "A04", "A05"]:
        base = CORPUS / cat / "positive"
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            ann = json.loads((d / "annotation.json").read_text(encoding="utf-8"))
            code = corpus_code(d)
            r = repo(tmp, f"t4-{ann['sample_id']}")
            (r / code[0].name).write_bytes(code[0].read_bytes())
            try:
                cand, change = pipeline(r, {})
            except subprocess.CalledProcessError:
                continue
            hunk_map = {}
            for c in change["changes"]:
                hunk_map[c["file"]] = changed_lines_new(c["hunks"])
            for c_ in cand["candidates"]:
                total += 1
                check(f"{c_['candidate_id']} 锚定在新增行",
                      c_["line"] in hunk_map.get(c_["file"], set()),
                      f"line {c_['line']}")
    print(f"  （检查 {total} 条候选）")


def t5_synthetic(tmp):
    print("T5 无靶场规则的合成夹具（1 正 1 负）")
    flask_imp = "from flask import Flask, request\napp = Flask(__name__)\n"

    # handler_without_auth
    r = repo(tmp, "t5-noauth-pos")
    cand, _ = pipeline(r, {"admin.py": flask_imp
                           + '@app.route("/admin/delete/<int:uid>")\n'
                           + "def delete_user(uid):\n    return 'deleted'\n"})
    check("noauth 正例产 handler_without_auth",
          any(c["pattern"] == "handler_without_auth" for c in cand["candidates"]))
    r = repo(tmp, "t5-noauth-neg")
    cand, _ = pipeline(r, {"admin.py": flask_imp
                           + "def login_required(f):\n    return f\n"
                           + '@app.route("/admin/delete/<int:uid>")\n'
                           + "@login_required\n"
                           + "def delete_user(uid):\n    return 'deleted'\n"})
    check("noauth 负例（@login_required）不产出",
          not any(c["pattern"] == "handler_without_auth" for c in cand["candidates"]))

    # csrf_state_change
    r = repo(tmp, "t5-csrf-pos")
    cand, _ = pipeline(r, {"transfer.py": flask_imp
                           + '@app.route("/transfer", methods=["POST"])\n'
                           + "def transfer():\n    amt = request.form.get('amount')\n    return 'ok'\n"})
    check("csrf 正例产 csrf_state_change",
          any(c["pattern"] == "csrf_state_change" for c in cand["candidates"]))
    r = repo(tmp, "t5-csrf-neg")
    cand, _ = pipeline(r, {"transfer.py": flask_imp
                           + '@app.route("/transfer", methods=["POST"])\n'
                           + "def transfer():\n    if request.form.get('_token') is None:\n"
                           + "        return 'bad', 403\n    return 'ok'\n"})
    check("csrf 负例（有 _token 检查）不产出",
          not any(c["pattern"] == "csrf_state_change" for c in cand["candidates"]))

    # xxe_parser
    r = repo(tmp, "t5-xxe-pos")
    cand, _ = pipeline(r, {"xmlparse.py":
                           "import xml.etree.ElementTree as ET\n"
                           "def parse(xml):\n"
                           "    parser = ET.XMLParser(resolve_entities=True)\n"
                           "    return ET.fromstring(xml, parser=parser)\n"})
    check("xxe 正例产 xxe_parser",
          any(c["pattern"] == "xxe_parser" for c in cand["candidates"]))
    r = repo(tmp, "t5-xxe-neg")
    cand, _ = pipeline(r, {"xmlparse.py":
                           "import xml.etree.ElementTree as ET\n"
                           "def parse(xml):\n"
                           "    return ET.fromstring(xml)\n"})
    check("xxe 负例（默认安全解析）不产出",
          not any(c["pattern"] == "xxe_parser" for c in cand["candidates"]))

    # missing_lockfile
    r = repo(tmp, "t5-lock-pos")
    cand, _ = pipeline(r, {"requirements.txt": "flask==2.3.2\n"})
    check("missing_lockfile 正例（无锁文件）产出",
          any(c["pattern"] == "missing_lockfile" for c in cand["candidates"]))
    r = repo(tmp, "t5-lock-neg")
    cand, _ = pipeline(r, {"requirements.txt": "flask==2.3.2\n",
                           "requirements.lock": "flask==2.3.2\n"})
    check("missing_lockfile 负例（有锁文件）不产出",
          not any(c["pattern"] == "missing_lockfile" for c in cand["candidates"]))

    # untrusted_registry
    r = repo(tmp, "t5-reg-pos")
    cand, _ = pipeline(r, {"requirements.txt": "--index-url http://evil.example.com/simple\n"
                                                 "flask==2.3.2\n"})
    check("untrusted_registry 正例（http 非官方源）产出",
          any(c["pattern"] == "untrusted_registry" for c in cand["candidates"]))
    r = repo(tmp, "t5-reg-neg")
    cand, _ = pipeline(r, {"requirements.txt": "--index-url https://pypi.org/simple\n"
                                                 "flask==2.3.2\n"})
    check("untrusted_registry 负例（官方源）不产出",
          not any(c["pattern"] == "untrusted_registry" for c in cand["candidates"]))

    # xss_innerHTML
    r = repo(tmp, "t5-xss-pos")
    cand, _ = pipeline(r, {"app.js":
                           "const box = document.getElementById('box');\n"
                           "const userInput = location.hash.slice(1);\n"
                           "box.innerHTML = userInput;\n"})
    check("xss 正例产 xss_innerHTML",
          any(c["pattern"] == "xss_innerHTML" for c in cand["candidates"]))
    r = repo(tmp, "t5-xss-neg")
    cand, _ = pipeline(r, {"app.js":
                           "const box = document.getElementById('box');\n"
                           'box.innerHTML = "<b>ok</b>";\n'})
    check("xss 负例（字面量）不产出",
          not any(c["pattern"] == "xss_innerHTML" for c in cand["candidates"]))


def t6_registry_coverage():
    print("T6 registry 18 条规则全部有检测器")
    reg = {r["name"] for r in json.loads(REGISTRY.read_text(encoding="utf-8"))["rules"]}
    missing = reg - set(DETECTORS)
    check("registry 全部在 DETECTORS", not missing, f"missing {missing}")
    check("无多余检测器", set(DETECTORS) - reg == set(), f"extra {set(DETECTORS) - reg}")


def t7_contract(tmp):
    print("T7 候选契约：字段 / 枚举 / 唯一性")
    d = CORPUS / "A05" / "positive" / "A05-sql-001"
    r = repo(tmp, "t7-contract")
    code = corpus_code(d)
    (r / code[0].name).write_bytes(code[0].read_bytes())
    cand, _ = pipeline(r, {})
    ids = []
    kinds = set()
    confs = set()
    for c in cand["candidates"]:
        ids.append(c["candidate_id"])
        confs.add(c["confidence"])
        for e in c["evidence"]:
            kinds.add(e["kind"])
        check("候选字段齐全",
              {"candidate_id", "category", "pattern", "file", "line", "confidence",
               "evidence", "context"}.issubset(c.keys()))
        check("context 非空", bool(c["context"]))
    check("candidate_id 唯一", len(ids) == len(set(ids)))
    check("confidence 枚举", confs <= {"high", "medium", "low"}, f"got {confs}")
    check("evidence kind 枚举", kinds <= {"endpoint", "user_controlled", "sink", "config", "auth", "sanitizer"},
          f"got {kinds}")
    check("meta.candidates_total 一致", cand["meta"]["candidates_total"] == len(ids))


def main():
    tmp = Path(tempfile.mkdtemp(prefix="m4_signal_"))
    try:
        t1_positives(tmp)
        t2_negatives(tmp)
        t3_redaction(tmp)
        t4_changed_anchor(tmp)
        t5_synthetic(tmp)
        t6_registry_coverage()
        t7_contract(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total, failed = len(_results), _results.count(False)
    print(f"\n== {total - failed}/{total} 通过 ==")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
