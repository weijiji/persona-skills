#!/usr/bin/env python3
"""
⑧ 报告类别编号门禁 验收测试（无第三方依赖，仅 python3）。

用法: python tests/report/run_tests.py
背景: SECURITY_REVIEW.md 的「OWASP 2025」列曾把 CWE-89 标成 A03（官方 OWASP 编号），
而项目分类基线是 A05 注入。本测试锁定：report_check 对错标报告必红、修正后必绿，
并锁定 CWE→A 基线与漂移检测。

覆盖:
  T1 基线锁定：CWE-89/78/79/94 → A05，CWE-601 → A10，CWE-918/639 → A01，CWE-327 → A04
  T2 错标必红：CWE-89 标 A03 → error；CWE-601 标 A01 → error（即用户报告的 bug）
  T3 修正必绿：同行改成 A05 / A10 → 无 error
  T4 全链路 CLI：真实报告表格（错标）→ 退出码 1；修正版 → 退出码 0（--json -o 落盘）
  T5 未覆盖 CWE：CWE-22 无注记 → error；带「官方，项目未覆盖」注记 → 放行
  T6 标签软检查：A04 设计缺陷（规范应为 加密失败）→ warning 非 error
  T7 registry 漂移：registry 里 sql_concat→A03 → 登记 DRIFT（与基线冲突）
  T8 正文管道符不误判：``MD5"|"SHA1"`` 正文行不算表格行（不误报 CWE）
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / "code-review" / "workflow"
REPORT_CHECK = WORKFLOW / "report_check.py"

sys.path.insert(0, str(WORKFLOW))
from report_check import (CANONICAL_CWE_CATS, CATEGORY_LABELS, check_report,  # noqa: E402
                          load_registry, parse_table_rows)

_results: list[bool] = []


def check(name, cond, detail=""):
    _results.append(bool(cond))
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def errors_of(issues):
    return [i for i in issues if i["level"] == "error"]


def warnings_of(issues):
    return [i for i in issues if i["level"] == "warning"]


# ---- 与真实故障报告 logs/SECURITY_REVIEW.md 相同的表格行（错标版本）----

BAD_ROWS = """| 1 | A05 注入 | CWE-78 | PingController.java:26-29 | 命令注入 → RCE |
| 2 | A03 注入 | CWE-89 | ProdutoController.java:23 | SQL 注入 → 读全表 |
| 3 | A01 访问控制 | CWE-918 | ProxyController.java:25 | SSRF |
| 4 | A01 访问控制 | CWE-639 | NotasController.java:20-27 | IDOR |
| 5 | A01 访问控制 | — | pom.xml:29-38 | 系统级无鉴权 |
| 6 | A03 注入 | CWE-79 | BuscaController.java:14-15 | 反射型 XSS |
| 7 | A01 访问控制 | CWE-601 | SairController.java:16-23 | 开放重定向 |
| 8 | A04 设计缺陷 | CWE-327 | SenhaService.java:12-16 | MD5 无盐口令哈希 |
| 9 | A05 注入 | CWE-22 | ArquivoService.java:9-11 | 路径穿越 |
"""

GOOD_ROWS = """| 1 | A05 注入 | CWE-78 | PingController.java:26-29 | 命令注入 → RCE |
| 2 | A05 注入 | CWE-89 | ProdutoController.java:23 | SQL 注入 → 读全表 |
| 3 | A01 访问控制 | CWE-918 | ProxyController.java:25 | SSRF |
| 4 | A01 访问控制 | CWE-639 | NotasController.java:20-27 | IDOR |
| 5 | A01 访问控制 | — | pom.xml:29-38 | 系统级无鉴权 |
| 6 | A05 注入 | CWE-79 | BuscaController.java:14-15 | 反射型 XSS |
| 7 | A10 SSRF | CWE-601 | SairController.java:16-23 | 开放重定向 |
| 8 | A04 加密失败 | CWE-327 | SenhaService.java:12-16 | MD5 无盐口令哈希 |
| 9 | A01 访问控制（官方映射，项目规则未覆盖） | CWE-22 | ArquivoService.java:9-11 | 路径穿越 |
"""

# 正文含管道符的行（如代码片段里的 MD5|SHA1），不该被当作表格行
PROSE_WITH_PIPE = "不相关正文（含管道符）\n- `MessageDigest.getInstance(\"MD5\"|\"SHA1\")` → 弱加密（CWE-327）\n| 1 | A05 注入 | CWE-78 | x | y |\n"


def t1_taxonomy():
    """CWE→A 基线锁定。这是本 bug 的分类权威：注入=A05（项目基线，非官方 A03）。"""
    cases = {
        "CWE-89": "A05", "CWE-78": "A05", "CWE-79": "A05", "CWE-94": "A05",
        "CWE-601": "A10", "CWE-918": "A01", "CWE-639": "A01", "CWE-862": "A01",
        "CWE-327": "A04", "CWE-1104": "A03", "CWE-295": "A08",
    }
    for cwe, cat in cases.items():
        check(f"T1 {cwe} ∈ 基线 {cat}", cat in CANONICAL_CWE_CATS[cwe])
    check("T1 CWE-22 不在基线（项目 27 规则未覆盖）", "CWE-22" not in CANONICAL_CWE_CATS)
    check("T1 A05 规范标签 = 注入", CATEGORY_LABELS["A05"] == "注入")
    check("T1 A10 规范标签 = SSRF", CATEGORY_LABELS["A10"] == "SSRF")
    check("T1 A04 规范标签 = 加密失败", CATEGORY_LABELS["A04"] == "加密失败")


def t2_bad_rows_error():
    """用户报告的 bug：CWE-89 被标 A03 → 必须报错；同类错标 CWE-601/A03、CWE-79/A03 也报。"""
    issues = check_report(BAD_ROWS)
    errs = errors_of(issues)
    cwe89 = [i for i in errs if i["cwe"] == "CWE-89"]
    check("T2 CWE-89 标 A03 → error", len(cwe89) == 1 and "A05" in cwe89[0]["expected"])
    check("T2 CWE-79 标 A03 → error",
          any(i["cwe"] == "CWE-79" for i in errs))
    check("T2 CWE-601 标 A01 → error（基线 A10）",
          any(i["cwe"] == "CWE-601" and "A10" in i["expected"] for i in errs))
    check("T2 CWE-22 无注记 → error（禁凭记忆编号）",
          any(i["cwe"] == "CWE-22" for i in errs))
    check("T2 至少 4 处 error", len(errs) >= 4, f"errors={len(errs)}")


def t3_good_rows_pass():
    """同一表格修正后 → 无 error（行 8 标签 warning 除外）。"""
    issues = check_report(GOOD_ROWS)
    errs = errors_of(issues)
    check("T3 修正版无 error", len(errs) == 0, f"errors={errs}")
    check("T3 修正版行 9（未覆盖 CWE 注记）放行为 note",
          any(i["level"] == "note" and i["cwe"] == "CWE-22" for i in issues))


def t4_cli(tmp):
    """端到端 CLI：错标报告退出码 1、修正报告退出码 0（--json -o 落盘 UTF-8）。"""
    bad = tmp / "bad.md"
    good = tmp / "good.md"
    bad.write_text(BAD_ROWS, encoding="utf-8")
    good.write_text(GOOD_ROWS, encoding="utf-8")

    out = tmp / "bad.json"
    r = subprocess.run([sys.executable, str(REPORT_CHECK), "-f", str(bad), "--json",
                        "-o", str(out)], capture_output=True, text=True)
    res = json.loads(out.read_text(encoding="utf-8"))
    check("T4 CLI 错标报告 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")
    check("T4 CLI json 含 CWE-89/A05 错误", res["ok"] is False
          and any(e["cwe"] == "CWE-89" and "A05" in e["expected"] for e in res["errors"]))

    out2 = tmp / "good.json"
    r2 = subprocess.run([sys.executable, str(REPORT_CHECK), "-f", str(good), "--json",
                         "-o", str(out2)], capture_output=True, text=True)
    res2 = json.loads(out2.read_text(encoding="utf-8"))
    check("T4 CLI 修正报告 → 退出码 0", r2.returncode == 0, f"rc={r2.returncode}")
    check("T4 CLI json ok=true", res2["ok"] is True)


def t5_unmapped_cwe():
    """未覆盖 CWE：无注记必红；带「官方/未覆盖」注记放行（note）。"""
    no_note = "| 9 | A05 注入 | CWE-22 | ArquivoService.java | 路径穿越 |\n"
    with_note = "| 9 | A01 访问控制（官方映射，项目规则未覆盖） | CWE-22 | ArquivoService.java | 路径穿越 |\n"
    e1 = errors_of(check_report(no_note))
    check("T5 CWE-22 无注记 → error", any(i["cwe"] == "CWE-22" for i in e1))
    e2 = errors_of(check_report(with_note))
    check("T5 CWE-22 带注记 → 无 error",
          not any(i["cwe"] == "CWE-22" for i in e2))


def t6_label_warning():
    """A 编号正确但标签不符 → warning 非 error（A04 设计缺陷 vs 规范 加密失败）。"""
    row = "| 8 | A04 设计缺陷 | CWE-327 | SenhaService.java | MD5 无盐口令哈希 |\n"
    issues = check_report(row)
    check("T6 A04 设计缺陷 → warning", any(i["level"] == "warning" for i in issues))
    check("T6 A04 编号本身正确 → 无 error", len(errors_of(issues)) == 0)


def t7_registry_drift():
    """registry 与基线冲突（sql_concat→A03）→ 登记 DRIFT。"""
    import json as _json
    with tempfile.TemporaryDirectory(prefix="report_drift_") as d:
        reg = {"rules": [
            {"name": "sql_concat", "category": "A03", "cwe": "CWE-89"},
            {"name": "command_concat", "category": "A05", "cwe": "CWE-78"},
        ]}
        p = Path(d) / "registry.json"
        p.write_text(_json.dumps(reg), encoding="utf-8")
        _, drift = load_registry(str(p))
    check("T7 sql_concat→A03 被登记为漂移",
          any("sql_concat" in x and "A03" in x for x in drift))
    check("T7 基线一致的规则不漂移",
          not any("command_concat" in x for x in drift))


def t8_prose_pipe_not_table():
    """正文里的管道符（MD5|SHA1）不算表格行，不得误报该行的 CWE-327。"""
    rows = parse_table_rows(PROSE_WITH_PIPE)
    check("T8 只识别行首 '|' 的表格行", len(rows) == 1, f"rows={rows}")
    issues = check_report(PROSE_WITH_PIPE)
    check("T8 正文 CWE-327 不误报",
          not any(i["cwe"] == "CWE-327" for i in errors_of(issues)))


def main():
    tmp = Path(tempfile.mkdtemp(prefix="report_check_"))
    try:
        t1_taxonomy()
        t2_bad_rows_error()
        t3_good_rows_pass()
        t4_cli(tmp)
        t5_unmapped_cwe()
        t6_label_warning()
        t7_registry_drift()
        t8_prose_pipe_not_table()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    total, failed = len(_results), _results.count(False)
    print(f"\n== {total - failed}/{total} 通过 ==")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
