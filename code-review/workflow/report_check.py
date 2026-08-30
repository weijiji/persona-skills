#!/usr/bin/env python3
"""
⑧ 报告门禁 — 校验 SECURITY_REVIEW.md 的「OWASP 2025」类别编号与项目分类基线一致（0 LLM token）。

用法:
    python workflow/report_check.py -f SECURITY_REVIEW.md
    python workflow/report_check.py -f SECURITY_REVIEW.md --registry rules/registry.json
    python workflow/report_check.py -f SECURITY_REVIEW.md --json   # 结构化结果（测试用）

背景（为什么要有它）:
  ⑧ 报告由 LLM 撰写。若报告者的上下文里没有权威类别表，它会凭 OWASP 记忆编号，
  把「CWE-89 SQL 注入」标成官方 OWASP 的 A03，而项目分类基线是 A05 注入 —— 两套
  编号混用导致报告错标（曾真实发生）。本工具是确定性门禁：报告定稿前必须通过。

类别编号唯一权威 = 项目分类基线（设计定稿 §5 + rules/registry.json）:
  A01 访问控制 / A02 安全配置错误 / A03 软件供应链 / A04 加密失败 / A05 注入 /
  A06 过时组件 / A07 认证失败 / A08 完整性失败 / A09 日志监控失败 / A10 SSRF。

规则:
  - 报告表格行若同时含 A 编号与 CWE，二者必须与基线一致（CWE 可多对一，如
    CWE-1104 → A03 或 A06）。
  - registry 未覆盖的 CWE（如路径穿越 CWE-22）不得凭记忆编号：表格里必须注明
    「官方/未覆盖/未映射」等依据，否则报错。
  - 类别名（标签）与基线不一致只给 warning（如 A04 写成「设计缺陷」而非「加密失败」）。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

# ---- 项目分类基线（单一权威；与 docs/workflow-design-locked.md §5 保持一致）----

# CWE → 允许的类别集合（一条 CWE 可能被多条规则映射到不同类别）
CANONICAL_CWE_CATS: dict[str, set[str]] = {
    "CWE-639": {"A01"}, "CWE-862": {"A01"}, "CWE-918": {"A01"}, "CWE-352": {"A01"},
    "CWE-489": {"A02"}, "CWE-798": {"A02", "A04"}, "CWE-942": {"A02"}, "CWE-611": {"A02"},
    "CWE-1104": {"A03", "A06"}, "CWE-1329": {"A03"},
    "CWE-327": {"A04"}, "CWE-338": {"A04"},
    "CWE-89": {"A05"}, "CWE-78": {"A05"}, "CWE-94": {"A05"}, "CWE-79": {"A05"},
    "CWE-916": {"A07"}, "CWE-521": {"A07"}, "CWE-613": {"A07"},
    "CWE-502": {"A08"}, "CWE-295": {"A08"},
    "CWE-117": {"A09"}, "CWE-209": {"A09"},
    "CWE-601": {"A10"},
}

# 类别 → 规范中文标签（报告「OWASP 2025」列应使用这些标签）
CATEGORY_LABELS: dict[str, str] = {
    "A01": "访问控制", "A02": "安全配置错误", "A03": "软件供应链",
    "A04": "加密失败", "A05": "注入", "A06": "过时组件",
    "A07": "认证失败", "A08": "完整性失败", "A09": "日志监控失败", "A10": "SSRF",
}

# CWE 未被基线覆盖时，报告必须带这类注记才可过关（禁止编造 A 编号）
UNMAPPED_NOTE_MARKERS = ("未映射", "未覆盖", "官方", "非项目规则", "参照 owasp", "参考 owasp")

_A_RE = re.compile(r"\b(A(?:0[1-9]|10))\b")  # A01..A10（注意 A10，别只匹配 A0x）
_CWE_RE = re.compile(r"\bCWE[- ]?([0-9]{2,4})\b", re.I)


def load_registry(path: str | None) -> tuple[list[dict], list[str]]:
    """读 registry.json → (规则列表, 漂移警告)。与基线不一致的规则登记为漂移。"""
    if not path:
        return [], []
    with open(path, encoding="utf-8") as f:
        rules = json.load(f).get("rules", [])
    drift = []
    for r in rules:
        cats = CANONICAL_CWE_CATS.get(r.get("cwe"))
        if cats is not None and r.get("category") not in cats:
            drift.append(
                f"registry 漂移: {r.get('name')} → {r.get('category')}/{r.get('cwe')}，"
                f"基线允许 {sorted(cats)}")
    return rules, drift


def parse_table_rows(text: str) -> list[tuple[int, list[str]]]:
    """按行拆出表格行（Markdown 表格 = 行首为 '|'）→ [(行号, 单元格列表)]。

    只认行首 '|' 的行，避免把正文里的管道符（如 ``MD5"|"SHA1``）误当表格。
    """
    rows = []
    for i, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if s.startswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            rows.append((i, cells))
    return rows


def check_report(text: str, cwe_cats: dict[str, set[str]] | None = None,
                 labels: dict[str, str] | None = None) -> list[dict]:
    """校验报告文本 → issues[{level, lineno, cwe, actual, expected, message}]。

    level: error（阻断）| warning（标签不一致）| note（信息）。
    """
    cwe_cats = cwe_cats or CANONICAL_CWE_CATS
    labels = labels or CATEGORY_LABELS
    issues: list[dict] = []

    for lineno, cells in parse_table_rows(text):
        # 找 A 编号所在的单元格与其后的标签文本
        a_cell_idx = next((k for k, c in enumerate(cells) if _A_RE.search(c)), None)
        cwe_tokens = sorted({_norm_cwe(m.group(1))
                             for c in cells for m in [_CWE_RE.search(c)] if m})
        if not cwe_tokens:
            continue  # 无 CWE，无从校验

        row_text = " ".join(cells).lower()
        annotated = any(mk in row_text for mk in UNMAPPED_NOTE_MARKERS)

        for cwe in cwe_tokens:
            allowed = cwe_cats.get(cwe)
            if allowed is None:
                if annotated:
                    issues.append({"level": "note", "lineno": lineno, "cwe": cwe,
                                   "message": f"{cwe} 不在项目基线覆盖，已注明依据（官方映射），跳过"})
                else:
                    issues.append({"level": "error", "lineno": lineno, "cwe": cwe,
                                   "expected": "注记（官方/未覆盖）",
                                   "message": f"{cwe} 不在项目基线覆盖，禁止凭记忆编号；"
                                              f"请注明依据（官方 OWASP 2025 映射）或标「未映射」"})
                continue

            if a_cell_idx is None:
                issues.append({"level": "error", "lineno": lineno, "cwe": cwe,
                               "expected": f"{sorted(allowed)}",
                               "message": f"{cwe} 所在行缺少 A 编号列，无法核对类别"})
                continue

            a_cell = cells[a_cell_idx]
            m = _A_RE.search(a_cell)
            actual = m.group(1)
            if actual not in allowed:
                issues.append({"level": "error", "lineno": lineno, "cwe": cwe,
                               "actual": actual, "expected": sorted(allowed),
                               "message": f"{cwe} 标为 {actual}，基线应为 {sorted(allowed)}"})
            else:
                # 标签软检查（不阻断）：A 编号正确但标签不匹配，提示用规范标签
                label = a_cell[m.end():].lstrip("：: -–—")
                canon = labels.get(actual)
                if label and canon and canon not in label and label not in canon:
                    issues.append({"level": "warning", "lineno": lineno, "cwe": cwe,
                                   "actual": f"{actual} {label}", "expected": f"{actual} {canon}",
                                   "message": f"{actual} 标签「{label}」与规范「{canon}」不一致"})
                else:
                    issues.append({"level": "note", "lineno": lineno, "cwe": cwe,
                                   "message": f"{cwe} → {actual} 通过"})
    return issues


def _norm_cwe(num: str) -> str:
    return f"CWE-{num}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="⑧ 报告类别编号门禁（0 LLM token）")
    ap.add_argument("-f", "--file", required=True, help="报告 Markdown 路径")
    ap.add_argument("--registry", default=None, help="rules/registry.json（可选，交叉核对漂移）")
    ap.add_argument("--json", action="store_true", help="输出结构化 JSON 结果（测试用）")
    ap.add_argument("-o", "--output", default=None, help="--json 结果写入文件（UTF-8，避开控制台编码）")
    args = ap.parse_args(argv)

    with open(args.file, encoding="utf-8") as f:
        text = f.read()

    rules, drift = load_registry(args.registry)
    issues = check_report(text)

    errors = [i for i in issues if i["level"] == "error"]
    warnings = [i for i in issues if i["level"] == "warning"]

    if args.json:
        result = {
            "file": args.file, "errors": errors, "warnings": warnings,
            "drift": drift, "ok": not errors,
        }
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        for i in issues:
            if i["level"] != "note":
                tag = {"error": "ERR", "warning": "WARN"}[i["level"]]
                print(f"[{tag}] L{i['lineno']}: {i['message']}")
        for d in drift:
            print(f"[DRIFT] {d}")
        if errors:
            print(f"[report_check] FAIL: {len(errors)} 处类别编号与基线不一致 - 先修正报告再定稿")
        elif drift:
            print("[report_check] PASS: 类别编号全部通过（registry 有漂移警告）")
        else:
            print("[report_check] PASS: 类别编号与项目基线一致")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
