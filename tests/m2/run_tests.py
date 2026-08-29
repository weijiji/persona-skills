#!/usr/bin/env python3
"""
M2 Git Collector 验收测试（无第三方依赖，仅 git + python3）。

用法: python tests/m2/run_tests.py
逐项构建临时 git 仓库 fixture → 跑 code-review/workflow/collect.py → 断言 change.json 契约。
覆盖: 默认模式(改/增/删/untracked) / --cached / BASE..HEAD / rename / binary / 空变更 / 语言推断。
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "code-review" / "workflow" / "collect.py"

_results: list[bool] = []


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True)


def git_out(cwd, *args):
    return subprocess.run(["git", *args], cwd=str(cwd), check=True,
                          capture_output=True, text=True).stdout


def init_repo(cwd):
    git(cwd, "init", "-q")
    git(cwd, "config", "user.email", "m2@test")
    git(cwd, "config", "user.name", "M2Test")


def commit_all(cwd, msg):
    git(cwd, "add", "-A")
    git(cwd, "commit", "-q", "-m", msg)


def run_collect(cwd, *extra):
    out = cwd / "out_change.json"
    subprocess.run([sys.executable, str(COLLECTOR), "-o", str(out), *extra],
                   cwd=str(cwd), check=True, capture_output=True, text=True)
    return json.loads(out.read_text(encoding="utf-8"))


def check(name, cond, detail=""):
    _results.append(bool(cond))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def new_abs(hunk, want_line):
    """把 hunk 体内的 + 行折算成新文件绝对行号 = new_start + 前面新增侧行数。"""
    before = 0
    for l in hunk["code"].split("\n"):
        if l.startswith("+"):
            if l == want_line:
                return hunk["new_start"] + before
            before += 1
        elif l.startswith(" "):
            before += 1
    return -1


def old_abs(hunk, want_line):
    """把 hunk 体内的 - 行折算成旧文件绝对行号。"""
    before = 0
    for l in hunk["code"].split("\n"):
        if l.startswith("-"):
            if l == want_line:
                return hunk["old_start"] + before
            before += 1
        elif l.startswith(" "):
            before += 1
    return -1


def t1_default_union(tmp):
    print("T1 默认模式: modified + untracked + deleted")
    d = tmp / "t1"
    d.mkdir()
    init_repo(d)
    (d / "a.py").write_text("line1\nline2\nline3\n", encoding="utf-8")
    (d / "c.py").write_text("dead1\ndead2\n", encoding="utf-8")
    commit_all(d, "v1")
    (d / "a.py").write_text("line1\nNEW_SECRET = 'sk-abc'\nline3\n", encoding="utf-8")
    (d / "b.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")
    (d / "c.py").unlink()

    ch = run_collect(d)
    check("meta.mode==worktree", ch["meta"]["mode"] == "worktree")
    files = {c["file"]: c for c in ch["changes"]}
    check("三个文件齐全 (a/b/c)", set(files) == {"a.py", "b.py", "c.py"})
    a = files["a.py"]
    h = a["hunks"][0]
    check("a.py 为 modified", a["status"] == "modified")
    check("a.py hunk new_start==1（-U3 整文件单 hunk）", h["new_start"] == 1)
    check("a.py 新增行落在新第 2 行", new_abs(h, "+NEW_SECRET = 'sk-abc'") == 2)
    check("a.py 删除行落在旧第 2 行", old_abs(h, "-line2") == 2)
    check("b.py added+untracked",
          files["b.py"]["status"] == "added" and files["b.py"].get("untracked") is True)
    check("c.py deleted", files["c.py"]["status"] == "deleted")
    check("meta.total_added==3 (a1+b2)", ch["meta"]["total_added"] == 3)
    check("meta.total_deleted==3 (a1+c2)", ch["meta"]["total_deleted"] == 3)
    check("meta.untracked_files==1", ch["meta"]["untracked_files"] == 1)
    check("meta.binary_files==0", ch["meta"]["binary_files"] == 0)


def t2_cached(tmp):
    print("T2 --cached: 仅 staged，untracked 排除")
    d = tmp / "t2"
    d.mkdir()
    init_repo(d)
    (d / "a.py").write_text("x1\nx2\n", encoding="utf-8")
    commit_all(d, "v1")
    (d / "a.py").write_text("x1\nSECRET = 'sk-1'\n", encoding="utf-8")
    git(d, "add", "a.py")
    (d / "b.py").write_text("untracked\n", encoding="utf-8")

    ch = run_collect(d, "--cached")
    check("仅含 a.py", [c["file"] for c in ch["changes"]] == ["a.py"])
    check("meta.mode==cached", ch["meta"]["mode"] == "cached")
    check("untracked 被排除", ch["meta"]["untracked_files"] == 0)
    check("SECRET 落在新第 2 行", new_abs(ch["changes"][0]["hunks"][0], "+SECRET = 'sk-1'") == 2)


def t3_range(tmp):
    print("T3 BASE..HEAD 范围")
    d = tmp / "t3"
    d.mkdir()
    init_repo(d)
    (d / "a.py").write_text("v1\n", encoding="utf-8")
    commit_all(d, "v1")
    (d / "a.py").write_text("v1\nEVIL = os.environ['X']\n", encoding="utf-8")
    commit_all(d, "v2")
    (d / "b.py").write_text("sql = 'select 1'\n", encoding="utf-8")
    commit_all(d, "v3")
    head = git_out(d, "rev-parse", "HEAD").strip()
    base = git_out(d, "rev-parse", "HEAD~2").strip()

    ch = run_collect(d, f"{base[:7]}..{head[:7]}")  # 短 hash 也应可解析
    files = {c["file"]: c for c in ch["changes"]}
    check("范围含 a.py+b.py", set(files) == {"a.py", "b.py"})
    check("meta.mode==range", ch["meta"]["mode"] == "range")
    check("base 解析为完整 hash", ch["meta"]["base"] == base)
    check("head 解析为完整 hash", ch["meta"]["head"] == head)
    check("EVIL 落在新第 2 行", new_abs(files["a.py"]["hunks"][0], "+EVIL = os.environ['X']") == 2)
    check("b.py 整文件新增 new_start==1/new_lines==1",
          files["b.py"]["hunks"][0]["new_start"] == 1 and files["b.py"]["hunks"][0]["new_lines"] == 1)


def t4_rename(tmp):
    print("T4a 纯 rename（100% 相似）→ 识别为 renamed、无 hunk")
    d = tmp / "t4a"
    d.mkdir()
    init_repo(d)
    (d / "old.py").write_text("a\nb\nc\n", encoding="utf-8")
    commit_all(d, "v1")
    git(d, "mv", "old.py", "new.py")

    ch = run_collect(d)
    nf = [c for c in ch["changes"] if c["file"] == "new.py"]
    check("纯 rename 识别为 renamed", len(nf) == 1 and nf[0]["status"] == "renamed")
    check("old_path 正确", bool(nf) and nf[0].get("old_path") == "old.py")
    check("纯 rename 无 hunk（省 token）", bool(nf) and nf[0]["hunks"] == [])

    print("T4b rename + edit（git 在部分环境不配对 → delete+add，Recall-safe）")
    d2 = tmp / "t4b"
    d2.mkdir()
    init_repo(d2)
    (d2 / "old.py").write_text("a\nb\nc\n", encoding="utf-8")
    commit_all(d2, "v1")
    git(d2, "mv", "old.py", "new.py")
    (d2 / "new.py").write_text("a\nb\nEVIL = 1\n", encoding="utf-8")

    ch2 = run_collect(d2)
    fm = {c["file"]: c for c in ch2["changes"]}
    check("新文件以 added 出现且带全量 hunk",
          fm.get("new.py", {}).get("status") == "added" and len(fm.get("new.py", {}).get("hunks", [])) == 1)
    check("EVIL 落在新第 3 行", new_abs(fm["new.py"]["hunks"][0], "+EVIL = 1") == 3)
    check("旧文件以 deleted 出现（内容不丢）", fm.get("old.py", {}).get("status") == "deleted")


def t5_binary(tmp):
    print("T5 二进制文件")
    d = tmp / "t5"
    d.mkdir()
    init_repo(d)
    (d / "blob.bin").write_bytes(b"\x00\x01\x02\x03")
    commit_all(d, "v1")
    (d / "blob.bin").write_bytes(b"\x04\x05\x06\x07")

    ch = run_collect(d)
    b = [c for c in ch["changes"] if c["file"] == "blob.bin"]
    check("binary 标记", len(b) == 1 and b[0]["binary"] is True)
    check("binary 无 hunk 内容", bool(b) and b[0]["hunks"] == [])
    check("meta.binary_files==1", ch["meta"]["binary_files"] == 1)


def t6_no_change(tmp):
    print("T6 无变更")
    d = tmp / "t6"
    d.mkdir()
    init_repo(d)
    (d / "a.py").write_text("ok\n", encoding="utf-8")
    commit_all(d, "v1")

    ch = run_collect(d)
    check("空变更", ch["changes"] == [] and ch["meta"]["total_files"] == 0)


def t7_lang(tmp):
    print("T7 语言/格式推断")
    d = tmp / "t7"
    d.mkdir()
    init_repo(d)
    (d / "requirements.txt").write_text("flask==2.0\n", encoding="utf-8")
    (d / "app.py").write_text("x=1\n", encoding="utf-8")
    commit_all(d, "v1")
    (d / "app.py").write_text("x=2\n", encoding="utf-8")
    (d / "requirements.txt").write_text("flask==2.1\n", encoding="utf-8")

    ch = run_collect(d)
    fm = {c["file"]: c["lang"] for c in ch["changes"]}
    check("python 识别", fm.get("app.py") == "python")
    check("manifest 识别", fm.get("requirements.txt") == "manifest")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="m2_collector_"))
    try:
        t1_default_union(tmp)
        t2_cached(tmp)
        t3_range(tmp)
        t4_rename(tmp)
        t5_binary(tmp)
        t6_no_change(tmp)
        t7_lang(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total, failed = len(_results), _results.count(False)
    print(f"\n== {total - failed}/{total} 通过 ==")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
