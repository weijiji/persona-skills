#!/usr/bin/env python3
"""
M3 Change Analyzer 验收测试（无第三方依赖，仅 git + python3）。

用法: python tests/m3/run_tests.py
逐项构建临时 git 仓库 fixture → 跑 collect.py → analyze.py → 断言 impact_map.json。
覆盖: python web 文件(A01/A05) / manifest(A03) / deleted / 无主题纯文件 /
      registry 完整性 / 全量靶场 positive 的规则资格桥接。
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
CORPUS = ROOT / "code-review" / "tests"
REGISTRY = ROOT / "code-review" / "rules" / "registry.json"

_results: list[bool] = []


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


def init_repo(cwd):
    git(cwd, "init", "-q")
    git(cwd, "config", "user.email", "m3@test")
    git(cwd, "config", "user.name", "M3Test")


def commit_all(cwd, msg):
    git(cwd, "add", "-A")
    git(cwd, "commit", "-q", "-m", msg)


def pipeline(cwd, *collect_extra):
    """collect → analyze，返回 (change, impact)。"""
    subprocess.run([sys.executable, str(COLLECTOR), "-o", "change.json", *collect_extra],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(ANALYZER), "-i", "change.json", "-o", "impact_map.json"],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    change = json.loads((cwd / "change.json").read_text(encoding="utf-8"))
    impact = json.loads((cwd / "impact_map.json").read_text(encoding="utf-8"))
    return change, impact


def check(name, cond, detail=""):
    _results.append(bool(cond))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def t1_python_web(tmp):
    print("T1 python web 文件（flask + SQL）→ A01/A05 + changed_functions 精确")
    d = tmp / "t1"
    d.mkdir()
    init_repo(d)
    (d / "app.py").write_text(
        "from flask import Flask, request\n"
        "import sqlite3\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    q = request.args.get('q')\n"
        "    cur = sqlite3.connect('app.db').cursor()\n"
        "    cur.execute(\"SELECT * FROM t WHERE name = '\" + q + \"'\")\n"
        "    return 'ok'\n"
        "\n"
        "def helper():\n"
        "    return 1\n", encoding="utf-8")
    commit_all(d, "v1")
    # 在 search() 里加一行，hunk 只触及 search
    (d / "app.py").write_text(
        "from flask import Flask, request\n"
        "import sqlite3\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    q = request.args.get('q')\n"
        "    cur = sqlite3.connect('app.db').cursor()\n"
        "    cur.execute(\"SELECT * FROM t WHERE name = '\" + q + \"'\")\n"
        "    rows = cur.fetchall()\n"
        "    return 'ok'\n"
        "\n"
        "def helper():\n"
        "    return 1\n", encoding="utf-8")

    _, impact = pipeline(d)
    check("tech_stack 识别 python+flask",
          "python" in impact["tech_stack"]["languages"] and "flask" in impact["tech_stack"]["frameworks"])
    f = next(x for x in impact["files"] if x["file"] == "app.py")
    check("framework==flask", f["framework"] == "flask")
    check("file_type==code", f["file_type"] == "code")
    check("risk_class 含 A01 与 A05",
          set(["A01", "A05"]).issubset(f["risk_class"]))
    check("topics 含 sql 与 web", {"sql", "web"}.issubset(f["topics"]))
    check("relevant_rules 含 sql_concat/eval_injection/idor",
          {"sql_concat", "eval_injection", "idor_missing_scope_check"}.issubset(f["relevant_rules"]))
    names = [x["name"] for x in f["changed_functions"]]
    check("changed_functions 只含 search（AST 边界精确）", names == ["search"], f"got {names}")


def t2_manifest(tmp):
    print("T2 manifest 文件（requirements.txt）→ A03")
    d = tmp / "t2"
    d.mkdir()
    init_repo(d)
    (d / "requirements.txt").write_text("flask==2.3.2\n", encoding="utf-8")
    commit_all(d, "v1")
    (d / "requirements.txt").write_text("flask==2.3.3\n", encoding="utf-8")

    _, impact = pipeline(d)
    f = next(x for x in impact["files"] if x["file"] == "requirements.txt")
    check("file_type==manifest", f["file_type"] == "manifest")
    check("risk_class==[A03,A06]", f["risk_class"] == ["A03", "A06"], f"got {f['risk_class']}")
    check("relevant 含 unpinned/missing_lockfile",
          {"unpinned_dependency", "missing_lockfile"}.issubset(f["relevant_rules"]))
    check("changed_functions 为空", f["changed_functions"] == [])


def t3_deleted(tmp):
    print("T3 deleted 文件 → 从旧侧识别被删函数")
    d = tmp / "t3"
    d.mkdir()
    init_repo(d)
    (d / "guard.py").write_text(
        "def security_check(request):\n"
        "    if request.user.role != 'admin':\n"
        "        raise PermissionError\n", encoding="utf-8")
    commit_all(d, "v1")
    (d / "guard.py").unlink()

    _, impact = pipeline(d)
    f = next(x for x in impact["files"] if x["file"] == "guard.py")
    check("status==deleted", f["status"] == "deleted")
    names = [x["name"] for x in f["changed_functions"]]
    check("从旧侧识别出 security_check", "security_check" in names, f"got {names}")


def t4_no_topic(tmp):
    print("T4 无主题纯文件 → risk_class 空（可被路由跳过，省 token）")
    d = tmp / "t4"
    d.mkdir()
    init_repo(d)
    (d / "plain.py").write_text("print('hello')\n", encoding="utf-8")
    commit_all(d, "v1")
    (d / "plain.py").write_text("print('hello again')\n", encoding="utf-8")

    _, impact = pipeline(d)
    f = next(x for x in impact["files"] if x["file"] == "plain.py")
    check("risk_class 为空", f["risk_class"] == [], f"got {f['risk_class']}")
    check("relevant_rules 为空", f["relevant_rules"] == [], f"got {f['relevant_rules']}")


def t5_registry_contract(tmp):
    print("T5 registry 契约：字段齐全 + 靶场 pattern 全覆盖")
    reg = json.loads(REGISTRY.read_text(encoding="utf-8"))["rules"]
    check("27 条规则", len(reg) == 27, f"got {len(reg)}")
    check("每条含 name/category/cwe/langs",
          all({"name", "category", "cwe", "langs"}.issubset(r) for r in reg))
    check("规则名唯一", len({r["name"] for r in reg}) == len(reg))
    check("category 合法", all(r["category"] in {"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"} for r in reg))
    names = {r["name"] for r in reg}
    missing = []
    for cat in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
        for polarity in ["positive", "negative"]:
            base = CORPUS / cat / polarity
            if not base.is_dir():
                continue
            for d in sorted(base.iterdir()):
                ann = d / "annotation.json"
                if not ann.exists():
                    continue
                a = json.loads(ann.read_text(encoding="utf-8"))
                if a["pattern"] not in names:
                    missing.append(f"{a['sample_id']}:{a['pattern']}")
    check("靶场全部 pattern 都在 registry", not missing, f"missing {missing}")


def t6_corpus_bridge(tmp):
    print("T6 桥接：全量 positive 样本的规则必须 eligible")
    reg_names = {r["name"] for r in json.loads(REGISTRY.read_text(encoding="utf-8"))["rules"]}
    samples = []
    for cat in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]:
        base = CORPUS / cat / "positive"
        if not base.is_dir():
            continue
        samples += sorted(base.iterdir())
    if not samples:
        print("  未找到靶场样本")
        return

    tmp2 = tmp / "bridge"
    tmp2.mkdir(exist_ok=True)
    for d in samples:
        ann = json.loads((d / "annotation.json").read_text(encoding="utf-8"))
        code = sorted(f for f in d.iterdir()
                      if f.name != "annotation.json"
                      and (f.suffix in {".py", ".json", ".txt"} or f.name.lower() == "dockerfile"))
        if not code:
            check(f"{ann['sample_id']} 无代码文件", False)
            continue
        repo = tmp2 / ann["sample_id"]
        repo.mkdir(exist_ok=True)
        init_repo(repo)
        git(repo, "commit", "--allow-empty", "-qm", "init")  # 空 init，让默认模式有 HEAD
        (repo / code[0].name).write_bytes(code[0].read_bytes())

        try:
            _, impact = pipeline(repo)
        except subprocess.CalledProcessError:
            check(f"{ann['sample_id']} 管线可跑", False)
            continue
        f = next((x for x in impact["files"] if x["file"] == code[0].name), None)
        check(f"{ann['sample_id']} 进入 impact_map",
              f is not None and f["status"] == "added")
        if f is None:
            continue
        check(f"{ann['sample_id']} 规则 {ann['pattern']} 被 eligible",
              ann["pattern"] in f["relevant_rules"], f"got {f['relevant_rules']}")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="m3_analyzer_"))
    try:
        t1_python_web(tmp)
        t2_manifest(tmp)
        t3_deleted(tmp)
        t4_no_topic(tmp)
        t5_registry_contract(tmp)
        t6_corpus_bridge(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total, failed = len(_results), _results.count(False)
    print(f"\n== {total - failed}/{total} 通过 ==")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
