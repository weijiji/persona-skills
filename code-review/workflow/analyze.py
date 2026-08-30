#!/usr/bin/env python3
"""
M3 Change Analyzer — 管线②：静态读 change.json → impact_map.json（纯静态，0 LLM token）。

用法:
    python workflow/analyze.py -i change.json -o impact_map.json

设计约束（design-locked §3 ② / ADR-0003 / ADR-0004）:
  - 只做文件级静态分类：tech_stack / framework / risk_class / changed_functions /
    relevant_rules。不做行级漏洞判定（那是 M4 Signal + M6 Reviewer）。
  - relevant_rules = 规则资格(lang) × risk_class 粗筛，来自 rules/registry.json。
    risk_class = 文件类型基底 + 改动代码的主题词；主题词是"提到了"，不是"命中漏洞"。
  - changed_functions：Python 用 stdlib ast 精确 def 边界；其它/解析失败用行级
    正则回退。只报被 hunk 触及的函数。
  - 密钥脱敏不在此做（同 M2——静态侧需要看到原文才能命中 hardcoded_secret）。
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from datetime import datetime, timezone

from gitutil import file_text, run_git

CODE_LANGS = {"python", "javascript", "typescript", "go", "java", "php", "ruby",
              "c", "cpp", "rust", "kotlin", "csharp", "swift"}
CONFIG_LANGS = {"json", "yaml", "toml", "xml"}

FILE_TYPE_BY_LANG = {
    "manifest": "manifest", "dockerfile": "dockerfile", "lockfile": "lockfile",
    "json": "config", "yaml": "config", "toml": "config", "xml": "config",
    "markdown": "doc", "text": "doc", "rst": "doc", "unknown": "unknown",
}

# 文件类型 → 默认暴露类别（不靠内容，类型即风险面）
FILE_TYPE_RISK_BASE = {
    "manifest": ["A03", "A06"], "dockerfile": ["A03", "A06"], "lockfile": ["A03", "A06"],
    "config": ["A02", "A04"], "code": [], "doc": [], "unknown": [],
}

# 改动代码主题词（正则，忽略大小写）→ 只在被 hunk 触及的新侧行上扫描
TOPIC_PATTERNS = {
    "sql": [r"sqlite3", r"psycopg", r"sqlalchemy", r"cursor\.execute", r"\.execute\s*\(",
            r"\.executemany", r"SELECT\s+", r"INSERT\s+INTO", r"UPDATE\s+", r"DELETE\s+FROM"],
    "cmd": [r"os\.system", r"os\.popen", r"subprocess", r"shell\s*=\s*True",
            r"child_process", r"Runtime\.exec", r"system\s*\("],
    "eval": [r"\beval\s*\(", r"\bexec\s*\(", r"compile\s*\("],
    "web": [r"@app\.route", r"@app\.(get|post|put|delete)\b", r"from flask", r"import flask",
            r"Flask\s*\(", r"django", r"fastapi", r"express", r"request\.args",
            r"request\.get_json", r"request\.form", r"render_template"],
    "auth": [r"login", r"logon", r"authenticate", r"session", r"cookie", r"permission",
             r"\brole\b", r"is_admin", r"current_user", r"jwt"],
    "url": [r"requests\.", r"urlopen", r"urllib", r"httpx", r"axios", r"aiohttp", r"fetch\s*\("],
    "xss": [r"innerHTML", r"insertAdjacentHTML", r"outerHTML", r"render_template_string",
            r"mark_safe", r"v-html", r"dangerouslySetInnerHTML"],
    "crypto": [r"hashlib", r"md5\s*\(", r"sha1\s*\(", r"cryptography", r"\bAES\b",
               r"random\.", r"\bsecrets\b", r"hmac", r"bcrypt", r"pbkdf2", r"cipher"],
    "hardkey": [r"sk-", r"api[_-]?key\s*[=:]", r"secret\s*[=:]", r"access[_-]?token\s*[=:]",
                r"bearer\s+[a-z0-9]{8,}", r"-----BEGIN"],
    "creds": [r"password", r"admin123", r"p@ssw0rd", r"root\s*[=:]\s*[\"']?root"],
    "xml": [r"xml\.etree", r"ElementTree", r"lxml", r"minidom", r"XMLParser", r"fromstring"],
    "cors": [r"\bCORS\b", r"allow_origins", r"access-control-allow-origin", r"cross_origin"],
    "debug": [r"debug\s*=\s*True", r"app\.run\s*\([^)]*debug", r"DEBUG\s*=\s*True", r"FLASK_DEBUG"],
    "deser": [r"\bpickle\b", r"cPickle", r"yaml\.load\s*\(", r"yaml\.load_all\s*\(",
              r"marshal\.loads\s*\(", r"joblib\.load\s*\(", r"read_pickle\s*\(", r"shelve\.open\s*\("],
    "tls": [r"verify\s*=\s*False", r"_create_unverified_context", r"check_hostname\s*=\s*False",
            r"\bCERT_NONE\b", r"disable_warnings\s*\("],
    "authn": [r"session\.permanent", r"permanent_session_lifetime", r"SESSION_COOKIE_",
              r"REMEMBER_COOKIE_", r"remember_me\s*=", r"timedelta\s*\(\s*days\s*=\s*\d",
              r"password_policy", r"min_length", r"check_password\s*\(|verify_password\s*\(|hash_password\s*\(",
              r"password\s*==|==\s*password"],
    "redirect": [r"redirect\s*\(|send_redirect\s*\(|redirect_to\s*=|Location\s*[=:]"],
    "logging": [r"logging\.(info|warning|error|debug|critical|exception)\s*\(",
                r"logger\.\w+\s*\(", r"getLogger\s*\("],
    "stacktrace": [r"traceback\.", r"format_exc\s*\(", r"print_exc\s*\(", r"exc_info"],
}

TOPIC_TO_CATEGORIES = {
    "sql": ["A05"], "cmd": ["A05"], "eval": ["A05"], "xss": ["A05"],
    "web": ["A01", "A05"], "auth": ["A01"], "url": ["A01"],
    "crypto": ["A04"], "hardkey": ["A04"],
    "creds": ["A02", "A07"], "xml": ["A02"], "cors": ["A02"], "debug": ["A02"],
    "deser": ["A08"], "tls": ["A08"],
    "authn": ["A07"], "redirect": ["A10"],
    "logging": ["A09"], "stacktrace": ["A09"],
}

# 框架识别：扫整个文件文本
FRAMEWORK_PATTERNS = {
    "flask": [r"from flask", r"import flask", r"Flask\s*\("],
    "django": [r"from django", r"import django"],
    "fastapi": [r"from fastapi", r"import fastapi"],
    "express": [r"require\s*\(\s*['\"]express", r"from ['\"]express['\"]"],
    "react": [r"from ['\"]react['\"]", r"require\s*\(\s*['\"]react['\"]"],
    "spring": [r"@RestController", r"org\.springframework"],
}

DEF_RE = re.compile(r"^\s*(?:class|def|async\s+def|function|func)\s+([A-Za-z_]\w*)", re.M)


def file_type_of(lang: str) -> str:
    if lang in CODE_LANGS:
        return "code"
    if lang in CONFIG_LANGS:
        return "config"
    return FILE_TYPE_BY_LANG.get(lang, "unknown")


def detect_topics(hunks: list[dict]) -> set[str]:
    """在 hunk 新侧行（+ 新增 / 空格 上下文）上找主题词。"""
    topics: set[str] = set()
    for h in hunks:
        for l in h["code"].split("\n"):
            if not l or not l.startswith(("+", " ")):
                continue
            text = l[1:]
            for topic, pats in TOPIC_PATTERNS.items():
                if topic in topics:
                    continue
                if any(re.search(p, text, re.IGNORECASE) for p in pats):
                    topics.add(topic)
    return topics


def detect_framework(text: str) -> str | None:
    for name, pats in FRAMEWORK_PATTERNS.items():
        if any(re.search(p, text, re.IGNORECASE) for p in pats):
            return name
    return None


def risk_class_of(file_type: str, topics: set[str]) -> list[str]:
    rc = set(FILE_TYPE_RISK_BASE.get(file_type, []))
    for t in topics:
        rc.update(TOPIC_TO_CATEGORIES.get(t, []))
    return sorted(rc)


def py_def_spans(text: str):
    """ast 解析 → [{name, kind, start, end}]；语法错误返回 None。"""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    spans = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            spans.append({"name": n.name,
                          "kind": "class" if isinstance(n, ast.ClassDef) else "function",
                          "start": n.lineno,
                          "end": getattr(n, "end_lineno", n.lineno)})
    return spans


def regex_def_spans(text: str) -> list[dict]:
    spans = []
    for m in DEF_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        spans.append({"name": m.group(1), "kind": "function", "start": line, "end": line})
    return spans


def _changed_side_lines(hunks: list[dict], side: str) -> set[int]:
    """真正被增删影响的行号集合。side=new 用新侧行号（- 行按新侧位置近似），side=old 用旧侧行号。
    只计 + 与 - 行，不把上下文行算作变更——避免短文件里 hunk 上下文探进相邻函数。"""
    out: set[int] = set()
    for h in hunks:
        new_abs, old_abs = h["new_start"], h["old_start"]
        for l in h["code"].split("\n"):
            if not l:
                continue
            if l.startswith("+"):
                if side == "new":
                    out.add(new_abs)
                new_abs += 1
            elif l.startswith("-"):
                if side == "old":
                    out.add(old_abs)
                elif side == "new":
                    out.add(new_abs)
                old_abs += 1
            elif l.startswith(" "):
                new_abs += 1
                old_abs += 1
    return out


def changed_functions(text: str, hunks: list[dict], use_old: bool = False) -> list[dict]:
    spans = py_def_spans(text)
    if spans is None:
        spans = regex_def_spans(text)
    changed = _changed_side_lines(hunks, "old" if use_old else "new")
    out = []
    for s in spans:
        if any(s["start"] <= ln <= s["end"] for ln in changed):
            out.append({"name": s["name"], "kind": s["kind"],
                        "line_start": s["start"], "line_end": s["end"]})
    return out


def load_registry() -> list[dict]:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "rules", "registry.json"), encoding="utf-8") as f:
        return json.load(f)["rules"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Change Analyzer → impact_map.json（管线②，纯静态）")
    ap.add_argument("-i", "--input", default="change.json")
    ap.add_argument("-o", "--output", default="impact_map.json")
    args = ap.parse_args(argv)

    with open(args.input, encoding="utf-8") as f:
        ch = json.load(f)

    root = os.getcwd()
    try:
        root = run_git(["rev-parse", "--show-toplevel"], root).strip()
    except RuntimeError:
        root = os.getcwd()

    registry = load_registry()
    meta = ch.get("meta", {})
    mode, head = meta.get("mode", "worktree"), meta.get("head")

    files_out = []
    for c in ch.get("changes", []):
        entry = {"file": c["file"], "lang": c.get("lang", "unknown"), "status": c["status"]}
        if c.get("binary"):
            entry.update({"file_type": "binary", "framework": None, "risk_class": [],
                          "topics": [], "changed_functions": [], "relevant_rules": []})
            files_out.append(entry)
            continue
        text = file_text(root, c["file"], mode, head, c["hunks"])
        file_type = file_type_of(c.get("lang", "unknown"))
        if text is None:
            entry.update({"file_type": file_type, "framework": None, "risk_class": [],
                          "topics": [], "changed_functions": [], "relevant_rules": []})
            files_out.append(entry)
            continue
        use_old = c["status"] == "deleted"
        if use_old:
            topics: set[str] = set()
        else:
            topics = detect_topics(c["hunks"])
        framework = detect_framework(text)
        risk_class = risk_class_of(file_type, topics)
        relevant = sorted({r["name"] for r in registry
                           if r["category"] in risk_class and c.get("lang") in r["langs"]})
        funcs = changed_functions(text, c["hunks"], use_old=use_old)
        entry.update({"file_type": file_type, "framework": framework,
                      "risk_class": risk_class, "topics": sorted(topics),
                      "changed_functions": funcs, "relevant_rules": relevant})
        files_out.append(entry)

    languages = sorted({f["lang"] for f in files_out if f["lang"] not in ("unknown", "binary")})
    frameworks = sorted({f["framework"] for f in files_out if f.get("framework")})
    impact = {
        "meta": {"base": meta.get("base"), "head": meta.get("head"), "mode": mode,
                 "generated_at": datetime.now(timezone.utc).isoformat(),
                 "source_change": os.path.basename(args.input)},
        "tech_stack": {"languages": languages, "frameworks": frameworks,
                       "files_total": len(files_out),
                       "lines_added": meta.get("total_added", 0),
                       "lines_deleted": meta.get("total_deleted", 0)},
        "files": files_out,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(impact, f, indent=2, ensure_ascii=False)

    print(f"[analyze] files={len(files_out)} langs={languages} frameworks={frameworks} "
          f"with_rules={sum(1 for x in files_out if x['relevant_rules'])} → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
