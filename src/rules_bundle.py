from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .rule_validation import validate_by_engine
from .util.textutil import sha256_hex
from .util.ziputil import write_zip
from .rule_router import decide_rule_scope


@dataclass
class RuleArtifact:
    source: str
    engine: str
    rule_path: str
    rule_text: str
    reference: str
    validated: bool
    validation_details: str
    fingerprint: str


def _fingerprint(rule_text: str) -> str:
    return sha256_hex((rule_text or "").encode("utf-8"))


def _engine_display(engine: str) -> str:
    e = (engine or "").lower()
    if e == "suricata":
        return "Suricata"
    if e == "snort2":
        return "Snort2"
    if e == "snort3":
        return "Snort3"
    if e == "sigma":
        return "Sigma"
    if e == "yara":
        return "YARA"
    return engine


def _engine_guidance_lines() -> List[str]:
    return [
        "### 6.0 Engine guidance (operational)",
        "- suricata: `suricata -T -c /etc/suricata/suricata.yaml -S rules.rules` 로 검증 후 적용",
        "- snort2: `snort -T -c snort.conf` 로 검증 후 include 적용",
        "- snort3: `snort -T -c snort.lua -R rules.rules` 로 검증 후 적용",
        "- sigma: `sigma validate rule.yml` 문법 검증 후 SIEM/EDR 타겟으로 변환",
        "- yara: `yara -C rule.yar` 컴파일 검증 후 호스트/파일 스캔 적용",
        "",
    ]


def filter_by_scope(cve: dict, official_hits: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    decision = decide_rule_scope(cve)
    keep: List[Dict[str, Any]] = []

    for h in official_hits:
        eng = (h.get("engine") or "").lower()
        if eng == "sigma" and decision.include_sigma:
            keep.append(h)
        elif eng in ("suricata", "snort2", "snort3") and decision.include_network_rules:
            keep.append(h)
        elif eng == "yara" and decision.include_yara:
            keep.append(h)

    return keep, decision.rationale


def validate_and_build_bundle(
    *,
    cfg,
    cve: dict,
    official_hits: List[Dict[str, Any]],
) -> Tuple[List[RuleArtifact], Optional[bytes], str, str]:
    scoped_hits, rationale = filter_by_scope(cve, official_hits)

    artifacts: List[RuleArtifact] = []
    zip_files: List[Tuple[str, bytes]] = []

    report_lines: List[str] = []
    report_lines.append("## 6) Rules (Official/Public)")
    report_lines.append(f"- Routing rationale: {rationale}")
    report_lines.append("")
    report_lines.extend(_engine_guidance_lines())

    if not scoped_hits:
        report_lines.append("- No official/public rules matched or allowed by routing policy.")
        return artifacts, None, sha256_hex(b""), "\n".join(report_lines) + "\n"

    report_lines.append("### 6.1 Matched rule files (pre-validation)")
    for h in scoped_hits:
        report_lines.append(
            f"- [{_engine_display(h.get('engine'))}] {h.get('source')} :: {h.get('rule_path')}  (ref: {h.get('reference')})"
        )
    report_lines.append("")

    report_lines.append("### 6.2 Validation results")
    for h in scoped_hits:
        engine = (h.get("engine") or "").lower()
        rule_text = h.get("rule_text") or ""
        fp = _fingerprint(rule_text)

        vr = validate_by_engine(engine, rule_text)
        ok = bool(vr.ok)

        artifacts.append(
            RuleArtifact(
                source=h.get("source") or "UNKNOWN",
                engine=engine,
                rule_path=h.get("rule_path") or "unknown",
                rule_text=rule_text,
                reference=h.get("reference") or "",
                validated=ok,
                validation_details=vr.details,
                fingerprint=fp,
            )
        )

        status = "PASS" if ok else "FAIL"
        report_lines.append(
            f"- {status} [{_engine_display(engine)}] {h.get('source')} :: {h.get('rule_path')} (fp {fp[:12]})"
        )
    report_lines.append("")

    pass_artifacts = [a for a in artifacts if a.validated]
    if pass_artifacts:
        report_lines.append("### 6.3 Rules bundle (validated only)")
        for a in pass_artifacts:
            zip_path = f"rules/{a.engine}/{a.source}/{a.rule_path}".replace("..", "_")
            zip_files.append((zip_path, (a.rule_text.strip() + "\n").encode("utf-8")))
            report_lines.append(f"- Included: {zip_path} (ref: {a.reference})")
        report_lines.append("")
        zip_bytes = write_zip(zip_files)
    else:
        zip_bytes = None
        report_lines.append("### 6.3 Rules bundle")
        report_lines.append("- No validated rules to bundle.")
        report_lines.append("")

    fails = [a for a in artifacts if not a.validated]
    if fails:
        report_lines.append("### 6.4 Validation failure details (first 800 chars each)")
        for a in fails:
            details = (a.validation_details or "").strip()
            if len(details) > 800:
                details = details[:800] + "…(truncated)"
            report_lines.append(f"- [{_engine_display(a.engine)}] {a.source} :: {a.rule_path} (fp {a.fingerprint[:12]})")
            report_lines.append("```")
            report_lines.append(details)
            report_lines.append("```")
        report_lines.append("")

    bundle_fp_src = "\n".join(sorted([a.fingerprint for a in pass_artifacts])).encode("utf-8")
    bundle_fingerprint = sha256_hex(bundle_fp_src)

    return artifacts, zip_bytes, bundle_fingerprint, "\n".join(report_lines).strip() + "\n"
