#!/usr/bin/env python3
"""工作流共享的 git/文件读取工具（② Change Analyzer / ③ Signal Engine 共用）。

从 analyze.py 抽出，避免两个静态阶段各自维护一套文件读取逻辑。零第三方依赖。
"""
from __future__ import annotations

import os
import subprocess


def run_git(args: list[str], cwd: str) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} 失败: {proc.stderr.strip()}")
    return proc.stdout


def reconstruct_old(hunks: list[dict]) -> str:
    """从 hunk 的旧侧行重建旧文件文本（用于 deleted / 读不到新版本时）。"""
    parts = []
    for h in hunks:
        for l in h["code"].split("\n"):
            if l.startswith("-"):
                parts.append(l[1:])
            elif l.startswith(" "):
                parts.append(l[1:])
    return "\n".join(parts) + "\n"


def file_text(root: str, path: str, mode: str, head: str, hunks: list[dict]) -> str | None:
    """读文件的新侧文本：range/cached 用 git show（commit 或索引），worktree 读磁盘，deleted 重建旧侧。"""
    if mode == "range" and head:
        try:
            return run_git(["show", f"{head}:{path}"], root)
        except RuntimeError:
            pass
    if mode == "cached":
        try:
            return run_git(["show", f":{path}"], root)
        except RuntimeError:
            pass
    p = os.path.join(root, path)
    if os.path.isfile(p):
        with open(p, "rb") as f:
            data = f.read()
        if b"\x00" in data[:8192]:
            return None
        for enc in ("utf-8", "latin-1"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return None
    return reconstruct_old(hunks)


def changed_lines_new(hunks: list[dict]) -> set[int]:
    """新侧被真正新增的行号集合（只计 + 行；- 行不推进新侧行号）。

    用于 Signal Engine 的"只锚定在变更行"约束：候选必须落在本次 diff 新增的行上。
    """
    out: set[int] = set()
    for h in hunks:
        n = h["new_start"]
        for l in h["code"].split("\n"):
            if not l:
                continue
            if l.startswith("+"):
                out.add(n)
                n += 1
            elif l.startswith(" "):
                n += 1
    return out
