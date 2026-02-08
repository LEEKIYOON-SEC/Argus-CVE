from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional


@dataclass
class ValidationResult:
    ok: bool
    details: str


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return p.returncode, (p.stdout or "")
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except Exception as e:
        return 125, f"EXCEPTION: {e}"


def validate_by_engine(engine: str, rule_text: str) -> ValidationResult:
    e = (engine or "").strip().lower()
    text = (rule_text or "").strip()
    if not text:
        return ValidationResult(False, "empty_rule_text")

    if e == "sigma":
        return _validate_sigma(text)
    if e == "yara":
        return _validate_yara(text)
    if e == "suricata":
        return _validate_suricata(text)
    if e == "snort2":
        return _validate_snort2(text)
    if e == "snort3":
        return _validate_snort3(text)

    # 알 수 없는 엔진은 실패(운영에서 모호성 제거)
    return ValidationResult(False, f"unsupported_engine: {engine}")


def _validate_sigma(text: str) -> ValidationResult:
    exe = _which("sigma")
    if not exe:
        return ValidationResult(False, "sigma-cli not installed (sigma command not found)")

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "rule.yml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.strip() + "\n")

        code, out = _run([exe, "validate", path], timeout=20)
        ok = (code == 0)
        return ValidationResult(ok, out.strip() or f"exit_code={code}")


def _validate_yara(text: str) -> ValidationResult:
    exe = _which("yara")
    if not exe:
        return ValidationResult(False, "yara not installed (yara command not found)")

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "rule.yar")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.strip() + "\n")

        # -C compile test
        code, out = _run([exe, "-C", path], timeout=20)
        ok = (code == 0)
        return ValidationResult(ok, out.strip() or f"exit_code={code}")


def _validate_suricata(text: str) -> ValidationResult:
    exe = _which("suricata")
    if not exe:
        return ValidationResult(False, "suricata not installed (suricata command not found)")

    with tempfile.TemporaryDirectory() as td:
        rules_path = os.path.join(td, "rules.rules")
        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(text.strip() + "\n")

        # 최소 config 생성: -S로 rules 로드
        cfg_path = os.path.join(td, "suricata.yaml")
        cfg = """
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.0.2.0/24]"
    EXTERNAL_NET: "any"
  port-groups:
    HTTP_PORTS: "80"
default-log-dir: .
outputs: []
"""
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(cfg.strip() + "\n")

        code, out = _run([exe, "-T", "-c", cfg_path, "-S", rules_path], timeout=25)
        ok = (code == 0)
        return ValidationResult(ok, out.strip() or f"exit_code={code}")


def _validate_snort2(text: str) -> ValidationResult:
    exe = _which("snort")
    if not exe:
        return ValidationResult(False, "snort (v2) not installed (snort command not found)")

    with tempfile.TemporaryDirectory() as td:
        rules_path = os.path.join(td, "local.rules")
        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(text.strip() + "\n")

        conf_path = os.path.join(td, "snort.conf")
        # 최소 snort.conf
        conf = f"""
var HOME_NET any
var EXTERNAL_NET any
var RULE_PATH {td}

include $RULE_PATH/local.rules
"""
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(conf.strip() + "\n")

        code, out = _run([exe, "-T", "-c", conf_path], timeout=25)
        ok = (code == 0)
        return ValidationResult(ok, out.strip() or f"exit_code={code}")


def _validate_snort3(text: str) -> ValidationResult:
    # ubuntu 패키지 기준 snort3 실행 파일은 보통 snort3
    exe = _which("snort3") or _which("snort")
    if not exe:
        return ValidationResult(False, "snort3 not installed (snort3/snort command not found)")

    with tempfile.TemporaryDirectory() as td:
        rules_path = os.path.join(td, "local.rules")
        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(text.strip() + "\n")

        lua_path = os.path.join(td, "snort.lua")
        # 최소 snort.lua: -R로 룰 로드
        lua = """
-- minimal snort.lua for validation
HOME_NET = 'any'
EXTERNAL_NET = 'any'
ips =
{
  enable_builtin_rules = false,
}
"""
        with open(lua_path, "w", encoding="utf-8") as f:
            f.write(lua.strip() + "\n")

        # Snort3는 -T -c snort.lua -R rules 형태
        code, out = _run([exe, "-T", "-c", lua_path, "-R", rules_path], timeout=25)
        ok = (code == 0)
        return ValidationResult(ok, out.strip() or f"exit_code={code}")
