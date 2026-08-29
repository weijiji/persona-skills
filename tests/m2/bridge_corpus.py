#!/usr/bin/env python3
"""
M1→M2 桥接验收：全量 Test Corpus 样本过一遍 Git Collector。

验证 Ground Truth（annotation.json 的 lines）与 change.json 的 hunk 行号能对上：
对每个样本，把代码文件作为"新增文件"放进临时 git 仓库，跑 collect.py，
断言 annotation 里的每个行号都落在某个 hunk 的新侧覆盖范围内。

用法: python tests/m2/bridge_corpus.py
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "code-review" / "workflow" / "collect.py"
CORPUS = ROOT / "code-review" / "tests"

CODE_EXTS = {".py", ".json", ".txt", ".dockerfile"}
_results: list[bool] = []


def check(name, cond, detail=""):
    _results.append(bool(cond))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def hunk_covers(hunks, line):
    return any(h["new_start"] <= line <= h["new_start"] + h["new_lines"] - 1 for h in hunks)


def main():
    samples = []
    for cat in ["A01", "A02", "A03", "A04", "A05"]:
        for polarity in ["positive", "negative"]:
            base = CORPUS / cat / polarity
            if not base.is_dir():
                continue
            for d in sorted(base.iterdir()):
                ann = d / "annotation.json"
                if ann.exists():
                    samples.append(d)

    if not samples:
        print("未找到任何样本，先跑 M1 靶场生成。")
        return 1

    tmp = Path(tempfile.mkdtemp(prefix="m2_bridge_"))
    try:
        for d in samples:
            ann = json.loads((d / "annotation.json").read_text(encoding="utf-8"))
            code_files = sorted(f for f in d.iterdir()
                                if f.name != "annotation.json"
                                and (f.suffix in CODE_EXTS or f.name.lower() == "dockerfile"))
            if not code_files:
                check(f"{ann['sample_id']} 无代码文件", False)
                continue
            code_file = code_files[0]
            repo = tmp / ann["sample_id"]
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "bridge@t"],
                           cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "bridge"],
                           cwd=repo, check=True, capture_output=True)
            # 先建一个空 init commit（collector 默认模式需要 HEAD），样本作为新增文件
            subprocess.run(["git", "commit", "--allow-empty", "-qm", "init"],
                           cwd=repo, check=True, capture_output=True)
            (repo / code_file.name).write_bytes(code_file.read_bytes())

            out = repo / "out_change.json"
            subprocess.run([sys.executable, str(COLLECTOR), "-o", str(out)],
                           cwd=repo, check=True, capture_output=True, text=True)
            ch = json.loads(out.read_text(encoding="utf-8"))

            entry = next((c for c in ch["changes"] if c["file"] == code_file.name), None)
            check(f"{ann['sample_id']} 样本进入 change.json",
                  entry is not None and entry.get("untracked") is True)
            if entry is None:
                continue

            ok_lines = all(hunk_covers(entry["hunks"], L) for L in ann["lines"])
            check(f"{ann['sample_id']} annotation lines 全部落在 hunk 新侧",
                  ok_lines, f"lines={ann['lines']}")
            if not ok_lines:
                check(f"  └ 实际 hunk 覆盖: {[(h['new_start'], h['new_start']+h['new_lines']-1) for h in entry['hunks']]}", True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total, failed = len(_results), _results.count(False)
    print(f"\n== {total - failed}/{total} 通过 ==")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
