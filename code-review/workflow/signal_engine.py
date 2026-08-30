#!/usr/bin/env python3
"""
M4 Signal Engine — 管线③：Pass1 grep（正则全量）+ Pass2 AST 邻接 → candidate.json。

用法:
    python workflow/signal_engine.py -c change.json -m impact_map.json -o candidate.json

注意：本文件不能叫 signal.py——会遮蔽 Python 标准库 signal 模块（subprocess 等
stdlib 内部要 import signal），导致循环导入。

设计约束（design-locked §3 ③ / ADR-0003 / ADR-0004）:
  - LLM 永不看完整 diff，只看到候选 + 有界证据窗口（context 即窗口，已脱敏）。
  - 静态阶段（本阶段）可以看到密钥原文用于判定，但输出给后续（LLM 侧）的
    evidence/context 一律 scrub（ADR-0003 四类禁入之"密钥原文"）。
  - AST 只做句法邻接 + 函数边界 + 函数内最小血缘（赋值→使用），不做完整数据流。
  - 候选只锚定在本次 diff 真正新增的行上（changed_lines_new），不改不改。
  - 每条候选按相关规则（relevant_rules，M3 已按 risk_class×lang 粗筛）跑检测器。
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from datetime import datetime, timezone

from gitutil import changed_lines_new, file_text, run_git

# --------------------------------------------------------------------------
# 规则元信息（category/cwe 来自 registry.json）
# --------------------------------------------------------------------------

RULE_TABLE: dict[str, dict] = {}


def load_registry() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "rules", "registry.json"), encoding="utf-8") as f:
        for r in json.load(f)["rules"]:
            RULE_TABLE[r["name"]] = {"category": r["category"], "cwe": r["cwe"]}


DETECTORS: dict[str, object] = {}


def detector(name: str):
    """注册器：把实现函数登记到 DETECTORS 表（rule_name -> fn）。"""
    def deco(fn):
        DETECTORS[name] = fn
        return fn
    return deco


def hit(line: int, confidence: str, evidence: list[tuple[str, str]]) -> dict:
    return {"line": line, "confidence": confidence, "evidence": evidence}


# --------------------------------------------------------------------------
# 脱敏（密钥原文永不进入 LLM 侧）
# --------------------------------------------------------------------------

PLACEHOLDER_WORDS = {
    "changeme", "change-me", "change_me", "your-key", "your_key", "yourpassword",
    "your_password", "your-api-key", "your_api_key", "example", "dummy", "todo",
    "foobar", "secret", "password", "passwd", "your-secret-key", "your_secret_key",
    "xxx", "mysecret", "my-secret", "secret-key", "test", "placeholder", "none",
}

PLACEHOLDER_FULL_RE = re.compile(
    r"^(?:your|my|example|sample|test|dummy|change|new)[-_]?[a-z0-9-]{2,20}$", re.I)

SECRET_PREFIX_RE = re.compile(
    r"^(sk-[A-Za-z0-9_\-]{8,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|-----BEGIN[A-Z ]*-----)", re.I)


def is_placeholder(val: str) -> bool:
    v = val.strip().strip("\"'")
    return v.lower() in PLACEHOLDER_WORDS or bool(PLACEHOLDER_FULL_RE.match(v))


def is_secret_literal(val: str) -> bool:
    v = val.strip().strip("\"'")
    if not v:
        return False
    if SECRET_PREFIX_RE.match(v):
        return True
    if len(v) < 16:
        return False
    if not re.search(r"[0-9]", v) or not re.search(r"[A-Za-z]", v):
        return False
    if is_placeholder(v):
        return False
    return True


def scrub_line(line: str) -> str:
    """把一行里长得像密钥的部分打成 ***。"""
    line = re.sub(r"\b(sk-[A-Za-z0-9_\-]{6,})\b", "sk-***", line)
    line = re.sub(r"\b(AKIA[0-9A-Z]{12,})\b", "AKIA***", line)
    line = re.sub(r"\b(ghp_[A-Za-z0-9]{10,})\b", "ghp_***", line)
    line = re.sub(r"(-----BEGIN [A-Z0-9 ]+-----)(.*)", r"\1***", line)
    line = re.sub(r"(Bearer\s+)[A-Za-z0-9._\-]+", r"\1***", line)
    line = re.sub(
        r"((?:api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|"
        r"authorization|authorisation)[A-Za-z0-9_]*\s*[=:]\s*[\"']?)[^\"',\s)]+",
        r"\1***", line, flags=re.I)
    return line


# --------------------------------------------------------------------------
# 句法邻接工具（AST / 函数边界）
# --------------------------------------------------------------------------

ROUTE_DECORATOR_RE = re.compile(r"\.(route|get|post|put|delete|patch)\s*\(")
PATH_RE = re.compile(r"(?:route|get|post|put|delete|patch)\s*\(\s*[\"']([^\"']*)")
METHODS_RE = re.compile(r"methods\s*=\s*\[([^\]]*)\]")
PATH_PARAM_RE = re.compile(r"<[^>]+>")


def collect_endpoints(tree, lines: list[str]) -> list[dict]:
    """带路由装饰器的函数 → [{node, decorators, start, end, path, methods}]。"""
    eps = []
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decs = [lines[d.lineno - 1] for d in n.decorator_list if d.lineno <= len(lines)]
        if not any(ROUTE_DECORATOR_RE.search(d) for d in decs):
            continue
        path, methods = None, None
        for d in decs:
            pm = PATH_RE.search(d)
            if pm and path is None:
                path = pm.group(1)
            mm = METHODS_RE.search(d)
            if mm and methods is None:
                methods = mm.group(1)
        eps.append({"node": n, "decorators": decs,
                    "start": n.lineno, "end": getattr(n, "end_lineno", n.lineno),
                    "path": path, "methods": methods})
    return eps


def function_at_line(tree, line: int):
    """包含 line 的最小函数 → (node, start, end) 或 None。"""
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            s, e = n.lineno, getattr(n, "end_lineno", n.lineno)
            if s <= line <= e and (best is None or (e - s) < (best[2] - best[1])):
                best = (n, s, e)
    return best


def find_function(tree, name: str):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def route_decorator(node, lines: list[str]) -> str:
    """def 上方连续的 @ 装饰器原文（用于 endpoint 证据）。"""
    out = []
    i = node.lineno - 2
    while i >= 0 and lines[i].lstrip().startswith("@"):
        out.append(lines[i])
        i -= 1
    return "\n".join(reversed(out))


def decorator_names(decorators: list[str]) -> list[str]:
    """只取装饰器的被调函数名（@app.route(...) → app.route），避免路径里的
    admin/user 等词被误判成鉴权守卫。"""
    out = []
    for d in decorators:
        m = re.search(r"@([\w.]+)\s*\(", d)
        out.append(m.group(1) if m else d.lstrip("@").strip())
    return out


def first_line_matching(body_lines: list[str], rx: re.Pattern) -> str:
    for l in body_lines:
        if rx.search(l):
            return l
    return ""


# --------------------------------------------------------------------------
# 认证/用户输入/资源访问 的判定（A01 用，句法级）
# --------------------------------------------------------------------------

GUARD_BODY_RE = re.compile(
    r"session\s*\[|current_user|\.role\b|\brole\b|is_authenticated|request\.headers|"
    r"verify|authoriz|permission|login_required|\.is_admin\b|require_role|"
    r"request\.auth|g\.user\b", re.I)
AUTH_DECORATOR_RE = re.compile(r"(login|auth|permission|require|admin|role|jwt|token)", re.I)
USER_INPUT_RE = re.compile(r"request\.(args|form|get_json|values|data)\b|request\.json|input\s*\(")
STORE_GET_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*get\s*\(")
NON_SOURCE_RECV = {"request", "session", "args", "form", "headers", "json", "data",
                   "values", "self", "g", "ctx", "config", "response", "settings"}
RESOURCE_CALL_RE = re.compile(r"\b(get|fetch|find|lookup|load|retrieve|read)_\w+\s*\(")
SENSITIVE_PATH_RE = re.compile(
    r"(admin|private|internal|user|account|profile|order|invoice|report|config|setting|"
    r"payment|billing|upload|download|delete|manage|control|panel|secret|key)", re.I)


# --------------------------------------------------------------------------
# 各规则检测器（Detector 接口：fn(fe, lines, changed, tree, root) -> list[Hit]）
# --------------------------------------------------------------------------

# ---------------- A01 越权访问控制 ----------------

@detector("idor_missing_scope_check")
def d_idor(fe, lines, changed, tree, root):
    """有用户输入且无归属校验的端点，按用户可控 id 取资源 → 候选。"""
    if tree is None:
        return []
    hits = []
    for ep in collect_endpoints(tree, lines):
        node = ep["node"]
        body_lines = lines[node.lineno - 1: ep["end"]]
        body = "\n".join(body_lines)
        if any(AUTH_DECORATOR_RE.search(n) for n in decorator_names(ep["decorators"])):
            continue
        if GUARD_BODY_RE.search(body):
            continue
        user_src = first_line_matching(body_lines, USER_INPUT_RE)
        if not user_src and not PATH_PARAM_RE.search(" ".join(ep["decorators"])):
            continue
        if not user_src:
            user_src = ep["decorators"][0]
        anchor = None
        for i, l in enumerate(body_lines):
            m = STORE_GET_RE.search(l)
            if m and m.group(1) not in NON_SOURCE_RECV:
                anchor = node.lineno + i
                break
        if anchor is None:
            for i, l in enumerate(body_lines):
                m = RESOURCE_CALL_RE.search(l)
                if not m:
                    continue
                callee = find_function(tree, m.group(0).rstrip("("))
                if callee is None:
                    continue
                inner = lines[callee.lineno - 1: getattr(callee, "end_lineno", callee.lineno)]
                for j, il in enumerate(inner):
                    gm = STORE_GET_RE.search(il)
                    if gm and gm.group(1) not in NON_SOURCE_RECV:
                        anchor = callee.lineno + j
                        break
                if anchor is not None:
                    break
        if anchor is None or anchor not in changed:
            continue
        hits.append(hit(anchor, "medium", [
            ("endpoint", ep["decorators"][0]),
            ("user_controlled", user_src),
            ("sink", lines[anchor - 1]),
            ("auth", "none"),
        ]))
    return hits


@detector("handler_without_auth")
def d_handler_no_auth(fe, lines, changed, tree, root):
    """敏感路径端点无任何鉴权守卫 → 候选（低置信，交由路由/复核）。"""
    if tree is None:
        return []
    hits = []
    for ep in collect_endpoints(tree, lines):
        if any(AUTH_DECORATOR_RE.search(n) for n in decorator_names(ep["decorators"])):
            continue
        body = "\n".join(lines[ep["start"] - 1: ep["end"]])
        if GUARD_BODY_RE.search(body):
            continue
        if not SENSITIVE_PATH_RE.search(ep["path"] or ""):
            continue
        anchor = next((i for i in range(ep["start"], ep["end"] + 1) if i in changed), None)
        if anchor is None:
            continue
        hits.append(hit(anchor, "low", [
            ("endpoint", ep["decorators"][0]),
            ("auth", "none"),
            ("config", f"path={ep['path']}"),
        ]))
    return hits


@detector("ssrf_user_url")
def d_ssrf(fe, lines, changed, tree, root):
    """服务端发起网络请求，URL 来自同函数内用户输入 → 候选。"""
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        m = re.search(r"\b(requests\.[a-z_]+|urlopen|urlretrieve|urllib\.[a-z_]+|"
                      r"httpx\.[a-z_]+|aiohttp\.[a-z_]+|http\.\w+|axios\.[a-z_]+|fetch\s*)\s*\(([^,)]*)",
                      l, re.I)
        if not m:
            continue
        arg = m.group(2).strip()
        if not arg or arg.startswith(('"', "'")):
            continue
        fn = function_at_line(tree, ln) if tree is not None else None
        body = "\n".join(lines[fn[1] - 1: fn[2]]) if fn else ""
        suspicious = False
        if re.search(r"request\.|input\s*\(|\.env\b|request\.json", arg):
            suspicious = True
        elif re.search(r"\{|\+|f[\"']", l):
            suspicious = True
        elif fn and re.search(r"\b" + re.escape(arg) + r"\b\s*=\s*[^\n]*(request\.|input\s*\()", body):
            suspicious = True
        if suspicious:
            hits.append(hit(ln, "medium", [
                ("endpoint", route_decorator(fn[0], lines) if fn else ""),
                ("user_controlled", first_line_matching(body.splitlines(), USER_INPUT_RE) if fn else ""),
                ("sink", l),
            ]))
    return hits


@detector("csrf_state_change")
def d_csrf(fe, lines, changed, tree, root):
    """POST/PUT/DELETE 状态变更端点无 CSRF 令牌/项目级防护 → 候选（低置信）。"""
    if tree is None:
        return []
    if re.search(r"CSRFProtect|\bcsrf\b", "\n".join(lines), re.I):
        return []
    hits = []
    for ep in collect_endpoints(tree, lines):
        dec = " ".join(ep["decorators"])
        methods = [x.strip().strip("\"'") for x in ep["methods"].split(",")] if ep["methods"] else []
        stateful = bool(set(methods) & {"POST", "PUT", "DELETE", "PATCH"})
        if not stateful and not re.search(r"\.(post|put|delete|patch)\s*\(", dec, re.I):
            continue
        body = "\n".join(lines[ep["start"] - 1: ep["end"]])
        if re.search(r"csrf|_token\b|X-CSRF", body, re.I):
            continue
        anchor = next((i for i in range(ep["start"], ep["end"] + 1) if i in changed), None)
        if anchor is None:
            continue
        hits.append(hit(anchor, "low", [
            ("endpoint", ep["decorators"][0]),
            ("config", f"methods={methods or 'POST(verb)'}"),
            ("auth", "no-csrf-token"),
        ]))
    return hits


# ---------------- A02 安全配置错误 ----------------

DEBUG_ON_RE = re.compile(r"\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b|\bDEBUG\s*=\s*1\b|"
                         r"FLASK_DEBUG\s*=\s*(1|True)\b|debug\s*=\s*1\b", re.I)
DEBUG_OFF_RE = re.compile(r"\bdebug\s*=\s*False\b|\bDEBUG\s*=\s*False\b|\bDEBUG\s*=\s*0\b|"
                          r"FLASK_DEBUG\s*=\s*(0|False)\b", re.I)


@detector("debug_enabled")
def d_debug(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if DEBUG_OFF_RE.search(l):
            continue
        if DEBUG_ON_RE.search(l):
            hits.append(hit(ln, "high", [("config", l)]))
    return hits


CRED_NAME_RE = re.compile(r"(password|passwd|pwd|username|user|admin|root|credential|account|login)", re.I)
WEAK_CRED = {"admin", "root", "password", "123456", "12345678", "123456789", "qwerty",
             "qwerty123", "letmein", "admin123", "p@ssw0rd", "p@ssword", "changeme",
             "toor", "111111", "000000", "pass", "password1"}
ASSIGN_QUOTED_RE = re.compile(r"([A-Za-z_]\w*)\s*[=:]\s*[\"']([^\"'\s]{1,64})[\"']")


@detector("default_credentials")
def d_creds(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        found = False
        for m in ASSIGN_QUOTED_RE.finditer(l):
            name, val = m.group(1), m.group(2)
            if CRED_NAME_RE.search(name) and val.lower() in WEAK_CRED:
                hits.append(hit(ln, "high", [("sink", scrub_line(l))]))
                found = True
                break
        if found:
            continue
        if (re.search(r"[\"'](admin123|password|123456|p@ssw0rd|qwerty|letmein|root)[\"']", l, re.I)
                and re.search(r"auth|login|sign", l, re.I)):
            hits.append(hit(ln, "medium", [("sink", scrub_line(l))]))
    return hits


CORS_OPEN_RE = re.compile(
    r"(allow_origins\s*=\s*\[?\s*[\"']?\*|origins\s*=\s*\[?\s*[\"']?\*|"
    r"allow_origins\s*:\s*\[?\s*[\"']?\*|origins\s*:\s*\[?\s*[\"']?\*|"
    r"access-control-allow-origin\s*[:=]\s*\*)", re.I)


@detector("permissive_cors")
def d_cors(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if CORS_OPEN_RE.search(l):
            hits.append(hit(ln, "high", [("config", l)]))
    return hits


XXE_RE = re.compile(
    r"(XMLParser\s*\([^)]*(resolve_entities\s*=\s*True|load_dtd\s*=\s*True|no_network\s*=\s*False)|"
    r"lxml\b.*\b(fromstring|parse|iterparse|XMLParser)\s*\(|"
    r"minidom\s*\.\s*(parseString|parse)\s*\(|"
    r"libxml2\b|xml2\b.*(external|entity))", re.I)


@detector("xxe_parser")
def d_xxe(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if XXE_RE.search(l):
            hits.append(hit(ln, "high", [("sink", l)]))
    return hits


# ---------------- A03 软件供应链 ----------------

PINNED_EQ_RE = re.compile(r"==\s*[\"']?[\w.]+\s*$")


def _unpinned_req_line(line: str) -> bool:
    s = line.strip()
    if not s or s.startswith("#") or s.startswith("-"):
        return False
    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\s*([<>=~!]+)\s*([A-Za-z0-9_.\-*]+))?\s*(?:;.*)?$", s)
    if not m:
        return False
    op = m.group(2)
    if op is None:
        return True        # 裸包名
    if op == "==":
        return False       # 精确锁定
    return True            # >= > < ~= 都是范围


def _unpinned_pkg_version(ver: str) -> bool:
    v = ver.strip().strip("\"'")
    if not v:
        return True
    if re.fullmatch(r"\d+(\.\d+){1,2}", v):
        return False       # 纯数字精确版本
    if v.startswith(("^", "~", ">", "<", "*")):
        return True
    if v in ("latest", "next", "workspace:*", "file:", "link:"):
        return True
    if "git+" in v or "http" in v:
        return True
    return False


PKG_JSON_VERSION_RE = re.compile(r"\"([\w@.\-/]+)\"\s*:\s*\"([^\"]+)\"")
PKG_JSON_SKIP_NAMES = {"name", "version", "description", "main", "license", "type",
                       "author", "engines", "private", "module", "exports", "homepage",
                       "repository", "keywords", "scripts", "bin", "files"}


@detector("unpinned_dependency")
def d_unpinned(fe, lines, changed, tree, root):
    base = os.path.basename(fe["file"]).lower()
    hits = []
    if base == "dockerfile":
        for ln in sorted(changed):
            l = lines[ln - 1].strip()
            if not l.upper().startswith("FROM"):
                continue
            if "@sha256:" in l:
                continue
            hits.append(hit(ln, "high", [("config", lines[ln - 1])]))
        return hits
    if base == "package.json":
        for ln in sorted(changed):
            l = lines[ln - 1]
            for m in PKG_JSON_VERSION_RE.finditer(l):
                name, ver = m.group(1), m.group(2)
                if name in PKG_JSON_SKIP_NAMES:
                    continue
                if _unpinned_pkg_version(ver):
                    hits.append(hit(ln, "high", [("config", l)]))
        return hits
    for ln in sorted(changed):
        if _unpinned_req_line(lines[ln - 1]):
            hits.append(hit(ln, "high", [("config", lines[ln - 1])]))
    return hits


LOCKFILE_FOR = {
    "requirements.txt": ["requirements.lock", "requirements.txt.lock", "Pipfile.lock", "poetry.lock"],
    "requirements.in": ["requirements.lock", "requirements.txt.lock", "Pipfile.lock", "poetry.lock"],
    "pipfile": ["Pipfile.lock", "poetry.lock"],
    "pyproject.toml": ["poetry.lock", "pdm.lock", "uv.lock"],
    "package.json": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"],
    "gemfile": ["Gemfile.lock"],
    "go.mod": ["go.sum"],
    "cargo.toml": ["Cargo.lock"],
    "composer.json": ["composer.lock"],
}


@detector("missing_lockfile")
def d_missing_lockfile(fe, lines, changed, tree, root):
    base = os.path.basename(fe["file"]).lower()
    want = LOCKFILE_FOR.get(base)
    if not want or not changed:
        return []
    if any(os.path.exists(os.path.join(root, lf)) for lf in want):
        return []
    anchor = min(changed)
    return [hit(anchor, "low", [("config", f"manifest={base} 仓库无锁文件（{want[0]}）")])]


OFFICIAL_REG = re.compile(
    r"(pypi\.org|pythonhosted\.org|npmjs\.org|registry\.npmjs\.org|index\.docker\.io|"
    r"registry\.docker\.io|docker\.io|ghcr\.io|gcr\.io|mcr\.microsoft\.com|maven\.org|"
    r"repo1\.maven\.org|repo\.maven\.apache\.org|rubygems\.org|golang\.org|"
    r"proxy\.golang\.org|crates\.io|packagist\.org|pkgs\.dev)", re.I)
REGISTRY_LINE_RE = re.compile(
    r"(index-url|extra-index-url|registry\s*=|@\w+\s*:\s*registry|publishConfig|"
    r"FROM\s+\S+@|docker\s+pull\s+\S+|yarn\s+config\s+set\s+registry)", re.I)
URL_RE = re.compile(r"https?://[^\s'\"\]]+")


@detector("untrusted_registry")
def d_untrusted_registry(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if not REGISTRY_LINE_RE.search(l):
            continue
        for u in URL_RE.findall(l):
            if OFFICIAL_REG.search(u):
                continue
            if (re.match(r"https://", u) and not re.search(r"localhost|127\.|\.local|\.internal", u, re.I)):
                continue   # https 私有域默认为可信，交给低置信候选
            hits.append(hit(ln, "low", [("config", scrub_line(l))]))
            break
    return hits


# ---------------- A04 密码学失败 ----------------

SECRET_NAME_RE = re.compile(r"(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|auth)", re.I)


@detector("hardcoded_secret")
def d_hardcoded_secret(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        for m in ASSIGN_QUOTED_RE.finditer(l):
            name, val = m.group(1), m.group(2)
            if not SECRET_NAME_RE.search(name):
                continue
            if is_placeholder(val):
                continue
            if is_secret_literal(val):
                hits.append(hit(ln, "high", [("sink", l)]))
                break
    return hits


WEAK_CRYPTO_RE = re.compile(r"\b(md5|sha1|rc4|des\b|des3\b|blowfish|weak_encryption)\b", re.I)
SAFE_CRYPTO_RE = re.compile(r"\b(pbkdf2|scrypt|argon2|sha256|sha384|sha512|sha3|bcrypt|blake2)\b", re.I)


@detector("weak_crypto")
def d_weak_crypto(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if SAFE_CRYPTO_RE.search(l):
            continue
        if WEAK_CRYPTO_RE.search(l):
            hits.append(hit(ln, "high", [("sink", l)]))
    return hits


RANDOM_USE_RE = re.compile(r"\brandom\.(random|randint|randrange|choice|choices|uniform|shuffle|sample|getrandbits)\s*\(")
RNG_SEC_CTX_RE = re.compile(r"(token|secret|password|passwd|otp|reset|nonce|salt|auth|verify|credential|pin|activation)", re.I)


@detector("weak_rng")
def d_weak_rng(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if not RANDOM_USE_RE.search(l):
            continue
        ctx = l
        fn = function_at_line(tree, ln) if tree is not None else None
        if fn:
            ctx = fn[0].name + " " + ctx
        if RNG_SEC_CTX_RE.search(ctx):
            hits.append(hit(ln, "medium", [("sink", l)]))
    return hits


# ---------------- A05 注入 ----------------

SQL_SINK_ATTRS = {"execute", "executemany", "executescript"}


def _sql_arg_interpolated(node):
    if not node.args:
        return False
    a = node.args[0]
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return False                      # 纯字符串字面量（含 ? / %s 参数化）→ 安全
    if isinstance(a, ast.JoinedStr):
        return True                       # f-string 插值
    if isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Add, ast.Mod)):
        return True                       # 拼接 / % 格式化
    if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr in ("format", "format_map"):
        return True                       # .format()
    if isinstance(a, (ast.Name, ast.Attribute)):
        return "variable"
    return False


@detector("sql_concat")
def d_sql(fe, lines, changed, tree, root):
    hits = []
    if tree is None:
        for ln in sorted(changed):
            l = lines[ln - 1]
            if re.search(r"\.(execute|executemany|executescript)\s*\([^)]*(\+|f[\"']|\$\{|\.format\s*\()", l, re.I):
                hits.append(hit(ln, "medium", [("sink", l), ("sanitizer", "none")]))
        return hits
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr in SQL_SINK_ATTRS):
            continue
        ln = n.lineno
        if ln not in changed:
            continue
        res = _sql_arg_interpolated(n)
        if res is True:
            hits.append(hit(ln, "high", [("sink", lines[ln - 1]), ("sanitizer", "none")]))
        elif res == "variable":
            hits.append(hit(ln, "low", [("sink", lines[ln - 1]), ("sanitizer", "none")]))
    return hits


OS_CMD_FUNCS = {"system", "popen", "popen2", "spawnl", "spawnlp", "spawnv", "spawnvp", "spawnve"}
SUBPROC_FUNCS = {"run", "call", "check_call", "check_output", "Popen", "call_output", "getoutput"}


@detector("command_concat")
def d_cmd(fe, lines, changed, tree, root):
    hits = []
    if tree is None:
        for ln in sorted(changed):
            l = lines[ln - 1]
            if (re.search(r"(os\.system|os\.popen|os\.spawn)\s*\([^)]*(\+|f[\"']|\$\{)",
                          l, re.I) or re.search(r"shell\s*=\s*True", l, re.I)):
                hits.append(hit(ln, "medium", [("sink", l), ("sanitizer", "none")]))
        return hits
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        ln = n.lineno
        if ln not in changed:
            continue
        f = n.func
        name = None
        if isinstance(f, ast.Name):
            name = f.id
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            name = f.attr
        shell_true = False
        for kw in n.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                shell_true = True
        if shell_true and name in SUBPROC_FUNCS:
            hits.append(hit(ln, "high", [("sink", lines[ln - 1]), ("sanitizer", "none")]))
            continue
        if name in OS_CMD_FUNCS:
            if n.args and not isinstance(n.args[0], ast.Constant):
                hits.append(hit(ln, "high", [("sink", lines[ln - 1])]))
            continue
        if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                and f.value.id == "subprocess" and name in SUBPROC_FUNCS):
            if n.args and isinstance(n.args[0], ast.List):
                continue                    # list 参数 + 无 shell → 安全
            if n.args and not isinstance(n.args[0], ast.Constant):
                hits.append(hit(ln, "medium", [("sink", lines[ln - 1])]))
    return hits


EVAL_FUNCS = {"eval", "exec", "compile", "__import__"}


@detector("eval_injection")
def d_eval(fe, lines, changed, tree, root):
    hits = []
    if tree is None:
        for ln in sorted(changed):
            l = lines[ln - 1]
            m = re.search(r"\b(eval|exec|compile)\s*\(\s*([^,)]+)", l)
            if m and not m.group(2).strip().startswith(('"', "'")):
                hits.append(hit(ln, "medium", [("sink", l)]))
        return hits
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id in EVAL_FUNCS):
            continue
        ln = n.lineno
        if ln not in changed:
            continue
        arg = n.args[0] if n.args else None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            continue                       # 字面量 → 安全
        conf = "medium"
        fn = function_at_line(tree, ln)
        if fn:
            body = "\n".join(lines[fn[1] - 1: fn[2]])
            if USER_INPUT_RE.search(body):
                conf = "high"
        hits.append(hit(ln, conf, [("sink", lines[ln - 1]),
                                   ("user_controlled", "同函数内有用户输入" if conf == "high" else "?"),
                                   ("sanitizer", "none")]))
    return hits


XSS_SINK_RE = re.compile(r"(\.innerHTML\s*=|insertAdjacentHTML\s*\(|outerHTML\s*=|"
                         r"document\.write\s*\(|dangerouslySetInnerHTML\s*=|v-html\s*=)", re.I)


@detector("xss_innerHTML")
def d_xss(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        m = XSS_SINK_RE.search(l)
        if not m:
            continue
        rhs = l[m.end():]
        if re.match(r"^\s*[\"']", rhs):
            continue                       # 字面量 → 安全
        hits.append(hit(ln, "medium", [("sink", l), ("sanitizer", "none")]))
    return hits


# ---------------- A06 漏洞与过时组件 ----------------

# Dockerfile FROM tag 语义：固定 = sha256 digest 或 ≥2 段数字（:3.11 / :3.12-slim）；
# 浮动 = 无 tag（默认 latest）/ 主版本单段（:3）/ 浮动词（latest/master/main/dev/edge/stable/unstable/next）
FLOATING_WORD_RE = re.compile(
    r"(latest|master|main|dev|develop|edge|stable|unstable|next)$", re.I)


def _docker_from_tag_floating(line: str) -> bool:
    l = line.strip()
    if not l.upper().startswith("FROM"):
        return False
    if "@sha256:" in l:
        return False
    m = re.search(r"FROM\s+[\w./-]+(?::([\w.-]+))?", l, re.I)
    tag = m.group(1) if m else None
    if not tag:
        return True
    num = re.match(r"^(\d+(?:\.\d+)*)", tag)
    if num and len(num.group(1).split(".")) >= 2:
        return False
    return True


@detector("floating_dependency")
def d_floating_dep(fe, lines, changed, tree, root):
    base = os.path.basename(fe["file"]).lower()
    hits = []
    if base == "dockerfile":
        for ln in sorted(changed):
            l = lines[ln - 1]
            if _docker_from_tag_floating(l):
                hits.append(hit(ln, "high", [("config", l)]))
        return hits
    if base == "package.json":
        for ln in sorted(changed):
            l = lines[ln - 1]
            for m in PKG_JSON_VERSION_RE.finditer(l):
                name, ver = m.group(1), m.group(2)
                if name in PKG_JSON_SKIP_NAMES:
                    continue
                if _unpinned_pkg_version(ver):
                    hits.append(hit(ln, "high", [("config", l)]))
        return hits
    for ln in sorted(changed):
        if _unpinned_req_line(lines[ln - 1]):
            hits.append(hit(ln, "high", [("config", lines[ln - 1])]))
    return hits


# ---------------- A07 身份识别与认证失败 ----------------

PASSWORD_NAME_RE = re.compile(r"\b(password|passwd|pwd|pin|credential|secret)\b", re.I)
HASH_CALL_RE = re.compile(
    r"\b(hashlib|bcrypt|pbkdf2|scrypt|argon2?|check_password_hash|verify_password|hmac|digest|blake2)\b", re.I)
PLAINTEXT_CMP_LIT_RE = re.compile(
    r"(?:[\"']([^\"']{1,32})[\"']\s*(==|!=)\s*\b(password|passwd|pwd)\b"
    r"|\b(password|passwd|pwd)\b\s*(==|!=)\s*[\"']([^\"']{1,32})[\"'])", re.I)
PLAINTEXT_CMP_ATTR_RE = re.compile(r"\b[\w.]*\.(password|passwd|pwd)\b\s*(==|!=)\s*[\w]+\b", re.I)


def fn_has_user_input(fn, lines) -> bool:
    if fn is None:
        return False
    body = "\n".join(lines[fn[1] - 1: fn[2]])
    return bool(USER_INPUT_RE.search(body))


@detector("plaintext_password_compare")
def d_plaintext_pwd(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if HASH_CALL_RE.search(l):
            continue                       # 哈希比对是安全用法，跳过
        if PLAINTEXT_CMP_LIT_RE.search(l) or PLAINTEXT_CMP_ATTR_RE.search(l):
            fn = function_at_line(tree, ln) if tree is not None else None
            conf = "high" if fn_has_user_input(fn, lines) else "medium"
            hits.append(hit(ln, conf, [("sink", l),
                                       ("user_controlled", "同函数内有用户输入" if conf == "high" else "?"),
                                       ("sanitizer", "none")]))
    return hits


POLICY_MINLEN_RE = re.compile(r"min_length\s*[\"']?\s*[=:]\s*([0-9]+)", re.I)
POLICY_LEN_RE = re.compile(r"len\s*\(\s*(password|passwd|pwd)\s*\)\s*<{1,2}\s*([0-9]+)", re.I)
POLICY_LEN_JS_RE = re.compile(r"\b(password|passwd|pwd)\.length\s*<\s*([0-9]+)", re.I)


@detector("weak_password_policy")
def d_weak_pwd_policy(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        weak = None
        m = POLICY_MINLEN_RE.search(l)
        if m and int(m.group(1)) < 8:
            weak = f"min_length={m.group(1)}"
        if weak is None:
            m = POLICY_LEN_RE.search(l)
            if m and int(m.group(2)) < 8:
                weak = f"len(password)<{m.group(2)}"
        if weak is None:
            m = POLICY_LEN_JS_RE.search(l)
            if m and int(m.group(2)) < 8:
                weak = f"password.length<{m.group(2)}"
        if weak is not None:
            hits.append(hit(ln, "medium", [("sink", l), ("sanitizer", "none")]))
    return hits


SESSION_PERM_RE = re.compile(r"session\.permanent\s*=\s*True\b", re.I)
SESSION_LIFETIME_LONG_RE = re.compile(
    r"\b(permanent_session_lifetime|remember_cookie_duration)\b.*?timedelta\s*\(\s*(?:days|weeks)\s*=\s*([0-9]+)", re.I)
SESSION_LIFETIME_SHORT_RE = re.compile(
    r"\b(permanent_session_lifetime|remember_cookie_duration)\b.*?timedelta\s*\(\s*(hours|minutes|seconds)", re.I)


@detector("session_expiry_weak")
def d_session_expiry(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if SESSION_LIFETIME_SHORT_RE.search(l):
            continue                       # 小时/分钟级短超时 → 安全
        if SESSION_PERM_RE.search(l):
            hits.append(hit(ln, "medium", [("sink", l), ("config", l), ("sanitizer", "none")]))
            continue
        m = SESSION_LIFETIME_LONG_RE.search(l)
        if m and int(m.group(2)) >= 7:
            hits.append(hit(ln, "medium", [("sink", l), ("config", l), ("sanitizer", "none")]))
    return hits


# ---------------- A08 软件与数据完整性失败 ----------------

DESER_OTHER_RE = re.compile(
    r"\b(pickle|cPickle|marshal|joblib|shelve)\.(load|loads)\s*\(|read_pickle\s*\(|torch\.load\s*\(", re.I)
DESER_YAML_RE = re.compile(r"\byaml\.load\s*\(", re.I)
DESER_YAML_SAFE_RE = re.compile(r"Loader\s*=\s*(?:yaml\.)?(?:CSafe|Safe|Full)Loader", re.I)


@detector("unsafe_deserialization")
def d_unsafe_deser(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        hit_line = False
        if DESER_OTHER_RE.search(l):
            hit_line = True
        elif DESER_YAML_RE.search(l) and not DESER_YAML_SAFE_RE.search(l):
            hit_line = True
        if not hit_line:
            continue
        fn = function_at_line(tree, ln) if tree is not None else None
        conf = "high" if fn_has_user_input(fn, lines) else "medium"
        hits.append(hit(ln, conf, [("sink", l), ("sanitizer", "none")]))
    return hits


TLS_VERIFY_FALSE_RE = re.compile(r"verify\s*=\s*False\b", re.I)
TLS_UNVERIFIED_CTX_RE = re.compile(r"ssl\._create_unverified_context\s*\(", re.I)
TLS_CERT_NONE_RE = re.compile(r"\bCERT_NONE\b", re.I)
TLS_CHECK_HOSTNAME_RE = re.compile(r"check_hostname\s*=\s*False\b", re.I)
TLS_DISABLE_WARN_RE = re.compile(r"urllib3\.disable_warnings\s*\(", re.I)


@detector("tls_verify_disabled")
def d_tls_verify(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if (TLS_VERIFY_FALSE_RE.search(l) or TLS_UNVERIFIED_CTX_RE.search(l)
                or TLS_CERT_NONE_RE.search(l) or TLS_CHECK_HOSTNAME_RE.search(l)):
            hits.append(hit(ln, "high", [("config", l), ("sink", l)]))
        elif TLS_DISABLE_WARN_RE.search(l):
            hits.append(hit(ln, "medium", [("config", l), ("sink", l)]))
    return hits


# ---------------- A09 安全日志与监控失败 ----------------

LOG_CALL_RE = re.compile(r"\b(logging|logger)\.(info|warning|error|debug|critical|exception)\s*\(", re.I)
LOG_INTERP_RE = re.compile(r"(f[\"']|[\"']\s*\+|\+[\"']|\.format\s*\(|`|\$\{)", re.I)


@detector("log_injection")
def d_log_injection(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        m = LOG_CALL_RE.search(l)
        if not m:
            continue
        arg_start = l.find("(", m.start())
        first_arg = l[arg_start + 1:].split(",", 1)[0] if arg_start != -1 else ""
        if LOG_INTERP_RE.search(first_arg) or re.search(r"request\.|input\s*\(", first_arg):
            fn = function_at_line(tree, ln) if tree is not None else None
            conf = "high" if fn_has_user_input(fn, lines) else "medium"
            hits.append(hit(ln, conf, [("sink", l),
                                       ("user_controlled", "同函数内有用户输入" if conf == "high" else "?"),
                                       ("sanitizer", "none")]))
    return hits


STACKTRACE_RETURN_RE = re.compile(
    r"\b(?:return|send|jsonify|Response)\b[^;\n]{0,60}\btraceback\.(format_exc|format_exception|format_stack)\b", re.I)
STACKTRACE_PRINT_RE = re.compile(r"\btraceback\.print_exc\s*\(", re.I)
STACKTRACE_STR_EXC_RE = re.compile(r"return\s+str\(\s*(e|err|exc|exception|error)\s*\)", re.I)


def _body_has_except(fn, lines) -> bool:
    body = "\n".join(lines[fn[1] - 1: fn[2]])
    return bool(re.search(r"\bexcept\b", body))


@detector("stacktrace_exposure")
def d_stacktrace(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        if STACKTRACE_RETURN_RE.search(l) or STACKTRACE_PRINT_RE.search(l):
            hits.append(hit(ln, "medium", [("sink", l), ("sanitizer", "none")]))
            continue
        if STACKTRACE_STR_EXC_RE.search(l):
            fn = function_at_line(tree, ln) if tree is not None else None
            if fn and _body_has_except(fn, lines):
                hits.append(hit(ln, "medium", [("sink", l), ("sanitizer", "none")]))
    return hits


# ---------------- A10 服务端请求伪造 ----------------

REDIRECT_CALL_RE = re.compile(r"\b(redirect|redirect_to|Redirect|send_redirect)\s*\(([^)]*)\)", re.I)
REDIRECT_HEADER_RE = re.compile(r"[\"']Location[\"']\s*[:=]\s*([^,\s}]+)", re.I)


@detector("open_redirect")
def d_open_redirect(fe, lines, changed, tree, root):
    hits = []
    for ln in sorted(changed):
        l = lines[ln - 1]
        m = REDIRECT_CALL_RE.search(l)
        if not m:
            mh = REDIRECT_HEADER_RE.search(l)
            if mh and mh.group(1).strip() and mh.group(1).strip()[0] not in "\"'":
                hits.append(hit(ln, "high", [("sink", l),
                                             ("user_controlled", mh.group(1)), ("sanitizer", "none")]))
            continue
        arg = m.group(2).strip()
        if not arg or arg[0] in "\"'":
            continue                       # 字面量 → 安全
        if "url_for" in arg:
            continue                       # 蓝图内部跳转 → 安全
        if re.search(r"request\.|input\s*\(", arg):
            hits.append(hit(ln, "high", [("sink", l),
                                         ("user_controlled", arg), ("sanitizer", "none")]))
            continue
        # 函数内赋值回溯：arg 是变量，查它在函数体里的赋值来源
        fn = function_at_line(tree, ln) if tree is not None else None
        rhs = ""
        if fn:
            body = "\n".join(lines[fn[1] - 1: fn[2]])
            am = re.search(r"\b" + re.escape(arg) + r"\b\s*=\s*([^\n]+)", body)
            if am:
                rhs = am.group(1).strip()
        if re.search(r"request\.|input\s*\(", rhs):
            hits.append(hit(ln, "high", [("sink", l),
                                         ("user_controlled", rhs), ("sanitizer", "none")]))
        elif re.search(r"\b[A-Z]\w*\.get\s*\(", rhs):
            continue                       # 白名单 dict 查表 → 安全
        else:
            hits.append(hit(ln, "medium", [("sink", l),
                                           ("user_controlled", rhs or arg), ("sanitizer", "none")]))
    return hits


# --------------------------------------------------------------------------
# 候选组装（证据窗口 + 脱敏）
# --------------------------------------------------------------------------

def context_for(fe, lines: list[str], line: int, tree) -> str:
    lo, hi = line - 4, line + 4
    if tree is not None and fe.get("lang") == "python":
        fn = function_at_line(tree, line)
        if fn:
            s, e = fn[1], fn[2]
            if e - s <= 12:
                lo, hi = s, e
            else:
                lo, hi = max(1, line - 6), line + 6
    lo, hi = max(1, lo), min(len(lines), hi)
    return "\n".join(scrub_line(x) for x in lines[lo - 1:hi])


def build_candidate(rule: str, fe, hit_: dict, lines: list[str], tree) -> dict:
    meta = RULE_TABLE[rule]
    line = hit_["line"]
    stem = re.sub(r"\W+", "_", os.path.splitext(os.path.basename(fe["file"]))[0])
    return {
        "candidate_id": f"{meta['category']}-{rule}-{stem}-{line}",
        "category": meta["category"],
        "pattern": rule,
        "file": fe["file"],
        "line": line,
        "confidence": hit_.get("confidence", "medium"),
        "evidence": [{"kind": k, "value": scrub_line(v)} for k, v in hit_["evidence"] if v],
        "context": context_for(fe, lines, line, tree),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Signal Engine → candidate.json（管线③，纯静态）")
    ap.add_argument("-c", "--change", default="change.json")
    ap.add_argument("-m", "--impact", default="impact_map.json")
    ap.add_argument("-o", "--output", default="candidate.json")
    args = ap.parse_args(argv)

    load_registry()
    with open(args.change, encoding="utf-8") as f:
        ch = json.load(f)
    with open(args.impact, encoding="utf-8") as f:
        impact = json.load(f)

    root = os.getcwd()
    try:
        root = run_git(["rev-parse", "--show-toplevel"], root).strip()
    except RuntimeError:
        root = os.getcwd()

    meta = ch.get("meta", {})
    mode, head = meta.get("mode", "worktree"), meta.get("head")
    change_by_file = {c["file"]: c for c in ch.get("changes", [])}

    candidates: list[dict] = []
    seen: set[tuple] = set()
    for fe in impact.get("files", []):
        if fe.get("file_type") == "binary" or fe.get("status") == "deleted":
            continue
        rules = fe.get("relevant_rules") or []
        if not rules:
            continue
        c = change_by_file.get(fe["file"])
        if c is None or c.get("binary"):
            continue
        text = file_text(root, fe["file"], mode, head, c.get("hunks", []))
        if text is None:
            continue
        lines = text.splitlines()
        changed = changed_lines_new(c.get("hunks", []))
        tree = ast.parse(text) if fe.get("lang") == "python" else None
        for rule in rules:
            det = DETECTORS.get(rule)
            if det is None:
                continue
            for h in det(fe, lines, changed, tree, root):
                if h["line"] not in changed:
                    continue                     # 只锚定在本次变更行
                key = (fe["file"], h["line"], rule)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(build_candidate(rule, fe, h, lines, tree))

    candidates.sort(key=lambda x: (x["category"], x["pattern"], x["file"], x["line"]))
    out = {
        "meta": {"source_change": os.path.basename(args.change),
                 "source_impact": os.path.basename(args.impact),
                 "generated_at": datetime.now(timezone.utc).isoformat(),
                 "candidates_total": len(candidates)},
        "candidates": candidates,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    by_cat: dict[str, int] = {}
    for c_ in candidates:
        by_cat[c_["pattern"]] = by_cat.get(c_["pattern"], 0) + 1
    print(f"[signal] candidates={len(candidates)} by_rule={by_cat} → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
