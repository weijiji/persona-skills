#!/usr/bin/env python3
"""
M2 Git Collector — 管线①：把一次 git 变更收成 change.json。

用法:
    python workflow/collect.py [-o change.json]             # 默认：working tree vs HEAD（staged+unstaged 并集）
    python workflow/collect.py --cached [-o change.json]    # 仅已 staged（index vs HEAD）
    python workflow/collect.py BASE..HEAD [-o change.json]  # 指定 commit 范围

契约: schemas/change.json（草稿，随里程碑细化）。设计约束见
docs/workflow-design-locked.md R6/R7/R8 / ADR-0003:
  - 永不静默截断: 任何变更都写入 change.json，大 diff 四档决策留给下游
    （Signal/Router），Collector 不做删减。
  - 二进制文件只记 binary:true、不携带内容；是否送 LLM 由下游决定。
  - 密钥原文/生成代码的过滤不在此做——静态 Signal 需要看到它们才能命中
    规则（如 hardcoded_secret）；LLM 侧脱敏在 M4 证据窗口构造时执行。
  - 默认模式额外收录 untracked 非二进制文件（status=added, untracked:true），
    避免"新建漏洞文件未被 git 跟踪"造成 Recall 漏检；--no-untracked 可关闭。
  - rename 检测跟随 git 默认（diff.renames=true）。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
BINARY_RE = re.compile(r"^Binary files? .+ differ$")

LANG_BY_EXT = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".rb": "ruby", ".php": "php", ".c": "c", ".h": "c", ".cc": "cpp",
    ".cpp": "cpp", ".cs": "csharp", ".swift": "swift",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".xml": "xml",
    ".toml": "toml", ".md": "markdown", ".txt": "text", ".rst": "text",
    ".html": "html", ".css": "css", ".sql": "sql", ".tf": "terraform",
    ".lock": "lockfile", ".sum": "lockfile",
}

MANIFEST_NAMES = {
    "requirements.txt", "requirements.in", "pipfile", "pipfile.lock",
    "poetry.lock", "gemfile", "gemfile.lock", "go.mod", "go.sum",
    "package.json", "yarn.lock", "pnpm-lock.yaml", "cargo.toml", "cargo.lock",
}


def lang_of(path: str) -> str:
    """按扩展名/文件名推断语言；lockfile/manifest 单独归类（A03 依赖扫描用）。"""
    base = os.path.basename(path).lower()
    if base == "dockerfile":
        return "dockerfile"
    if base in MANIFEST_NAMES:
        return "manifest"
    return LANG_BY_EXT.get(os.path.splitext(path)[1].lower(), "unknown")


def run_git(args: list[str], cwd: str) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} 失败: {proc.stderr.strip()}")
    return proc.stdout


def rev_parse(ref: str, cwd: str) -> str | None:
    try:
        return run_git(["rev-parse", ref], cwd).strip()
    except RuntimeError:
        return None


def _split_paths(rest: str) -> tuple[str, str]:
    """从 'a/old b/new' 拆出 (old_path, new_path)。含 ' b/' 的路径名罕见，M2 不处理。"""
    marker = " b/"
    if marker in rest:
        a, b = rest.split(marker, 1)
        a = a[2:] if a.startswith("a/") else a
        return a, b
    return rest, rest


def parse_unified_diff(diff: str) -> list[dict]:
    """解析 git 统一 diff → changes[]。逐文件：状态 + hunks（含原始行，带 +/-/空格前缀）。"""
    changes: list[dict] = []
    cur: dict | None = None
    hunk: dict | None = None
    lines = diff.split("\n")
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if line.startswith("diff --git "):
            if cur is not None:
                changes.append(cur)
            a, b = _split_paths(line[len("diff --git "):])
            cur = {"file": b, "old_path": None, "status": "modified",
                   "binary": False, "size_lines": 0, "hunks": []}
            hunk = None
        elif cur is None:
            pass  # 不应出现的前导垃圾
        elif line.startswith("rename from "):
            cur["old_path"] = line[len("rename from "):]
            cur["status"] = "renamed"
        elif line.startswith("rename to "):
            cur["file"] = line[len("rename to "):]
            cur["status"] = "renamed"
        elif line.startswith("new file mode"):
            cur["status"] = "added"
        elif line.startswith("deleted file mode"):
            cur["status"] = "deleted"
        elif BINARY_RE.match(line):
            cur["binary"] = True
            while i < n and not lines[i].startswith("diff --git "):
                i += 1
            continue
        elif HUNK_RE.match(line):
            m = HUNK_RE.match(line)
            old_start, old_len = int(m.group(1)), int(m.group(2) or "1")
            new_start, new_len = int(m.group(3)), int(m.group(4) or "1")
            hunk = {"old_start": old_start, "old_lines": old_len,
                    "new_start": new_start, "new_lines": new_len, "code": ""}
            cur["hunks"].append(hunk)
            # 受影响行数 = hunk 两侧较大者（新增/删除各看一侧）
            cur["size_lines"] += max(old_len, new_len)
        elif hunk is not None:
            hunk["code"] += line + "\n"
        # 其余 header 行（index / old mode / ---/+++ / similarity）忽略
        i += 1
    if cur is not None:
        changes.append(cur)
    return changes


def collect_untracked(cwd: str) -> list[dict]:
    """默认模式下把未跟踪的文本文件收成 status=added 条目（二进制只标记不带内容）。"""
    out = run_git(["ls-files", "--others", "--exclude-standard"], cwd)
    changes: list[dict] = []
    for path in out.splitlines():
        full = os.path.join(cwd, path)
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            continue
        entry = {"file": path, "old_path": None, "status": "added",
                 "binary": False, "size_lines": 0, "hunks": [], "untracked": True}
        if b"\x00" in data[:8192]:
            entry["binary"] = True
            changes.append(entry)
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = data.decode("latin-1")
            except Exception:
                entry["binary"] = True
                changes.append(entry)
                continue
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        entry["size_lines"] = len(lines)
        entry["hunks"].append({"old_start": 0, "old_lines": 0,
                               "new_start": 1, "new_lines": len(lines),
                               "code": "".join("+" + l + "\n" for l in lines)})
        changes.append(entry)
    return changes


def line_counts(changes: list[dict]) -> tuple[int, int]:
    """纯新增（+）与纯删除（-）行总数（排除 +++/--- 头）。"""
    added = deleted = 0
    for c in changes:
        for h in c["hunks"]:
            for l in h["code"].split("\n"):
                if l.startswith("+") and not l.startswith("+++"):
                    added += 1
                elif l.startswith("-") and not l.startswith("---"):
                    deleted += 1
    return added, deleted


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Git Collector → change.json（管线①）")
    ap.add_argument("-o", "--output", default="change.json", help="输出路径")
    ap.add_argument("--cached", action="store_true", help="仅已 staged（index vs HEAD）")
    ap.add_argument("--unified", type=int, default=3, help="hunk 上下文行数")
    ap.add_argument("--no-untracked", action="store_true", help="默认模式不收录 untracked 文件")
    ap.add_argument("range", nargs="?", default=None, help="BASE..HEAD commit 范围")
    args = ap.parse_args(argv)

    cwd = os.getcwd()
    root = run_git(["rev-parse", "--show-toplevel"], cwd).strip()
    head_hash = rev_parse("HEAD", root)

    mode, base, head = "worktree", head_hash, "WORKTREE"
    if args.cached:
        diff = run_git(["diff", "--cached", f"--unified={args.unified}"], root)
        mode, head = "cached", "INDEX"
    elif args.range:
        if ".." not in args.range:
            ap.error("range 需形如 BASE..HEAD")
        base_ref, head_ref = args.range.split("..", 1)
        base = rev_parse(base_ref, root)
        head = rev_parse(head_ref, root)
        if base is None or head is None:
            ap.error(f"无法解析范围 {args.range}（{base_ref} 或 {head_ref} 不存在）")
        diff = run_git(["diff", base_ref, head_ref, f"--unified={args.unified}"], root)
        mode = "range"
    else:
        if head_hash is None:
            ap.error("默认模式需要 HEAD（仓库还没有提交）。请改用 --cached 或 BASE..HEAD。")
        diff = run_git(["diff", "HEAD", f"--unified={args.unified}"], root)

    changes = parse_unified_diff(diff)
    if mode == "worktree" and not args.no_untracked:
        changes += collect_untracked(root)

    total_added, total_deleted = line_counts(changes)
    binary_files = sum(1 for c in changes if c["binary"])
    untracked_count = sum(1 for c in changes if c.get("untracked"))

    for c in changes:
        c["lang"] = lang_of(c["file"])
        if c["old_path"] is None:
            del c["old_path"]

    payload = {
        "meta": {
            "base": base,
            "head": head,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "total_files": len(changes),
            "total_added": total_added,
            "total_deleted": total_deleted,
            "binary_files": binary_files,
            "untracked_files": untracked_count,
        },
        "changes": changes,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"[collect] mode={mode} files={len(changes)} +{total_added} -{total_deleted} "
          f"(binary={binary_files} untracked={untracked_count}) → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
