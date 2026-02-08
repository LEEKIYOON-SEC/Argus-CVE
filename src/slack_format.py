from __future__ import annotations

from typing import Optional, Sequence

from .i18n_ko import ko_severity, ko_attack_vector, ko_yesno


def _fmt(v) -> str:
    if v is None:
        return "N/A"
    return str(v)


def _shorten(text: str, max_len: int = 900) -> str:
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[:max_len] + "…(생략)"


def _rule_snippet(rule_text: str, max_chars: int = 1200) -> str:
    t = (rule_text or "").strip()
    if len(t) <= max_chars:
        return t
    return t[:max_chars] + "\n…(truncated)"


def _engine_registration_guidance() -> str:
    # “등록 방식이 다르다” 요구 반영: 짧고 실용적으로
    return (
        "*룰 엔진/등록 가이드(요약)*\n"
        "- `suricata`: suricata.yaml의 rule-files에 추가 또는 `-S <rules>` 로드\n"
        "- `snort2`: snort.conf에 `include <rules>` 후 `snort -T -c snort.conf`로 검증\n"
        "- `snort3`: snort.lua 기반, `-R <rules>` 로드 후 `snort -T -c snort.lua -R rules` 검증\n"
        "- `sigma`: SIEM/EDR 변환(예: sigma-cli). `sigma validate`로 문법 검증\n"
        "- `yara`: 호스트/파일 스캔. `yara -C rule.yar`로 컴파일 검증\n"
    )


def format_slack_message(
    *,
    cve: dict,
    alert_type: str,
    notify_reason: str,
    change_kind: str,
    report_link: str,
    top_validated_rules: Optional[Sequence[dict]] = None,
    include_rule_blocks_max: int = 3,
    rules_zip_present: bool = False,
) -> str:
    cve_id = cve["cve_id"]
    cvss_score = cve.get("cvss_score")
    cvss_sev = ko_severity(cve.get("cvss_severity") or "")
    cvss_vec = cve.get("cvss_vector")
    av = ko_attack_vector(cve.get("attack_vector"))
    epss = cve.get("epss_score")
    epss_pct = cve.get("epss_percentile")
    kev = ko_yesno(bool(cve.get("is_cisa_kev") or False))
    kev_added = cve.get("kev_added_date") or "N/A"
    pub = cve.get("published_date") or (cve.get("date_published") or "N/A")
    upd = cve.get("last_modified_date") or (cve.get("date_updated") or "N/A")

    cwe = cve.get("cwe_ids") or []
    cwe_str = ", ".join(cwe[:20]) + (f" (+{len(cwe)-20} more)" if len(cwe) > 20 else "")
    refs = cve.get("references") or []
    refs_str = "\n".join([f"- {r}" for r in refs[:8]]) + (f"\n- ...(총 {len(refs)}개)" if len(refs) > 8 else "")

    desc_en = cve.get("description_en") or ""
    desc = _shorten(desc_en, 700)

    if alert_type == "NEW_CVE_PUBLISHED":
        title = "🆕 신규 CVE(PUBLISHED)"
    elif alert_type == "UPDATE_ESCALATION":
        title = "🚨 승격/재알림(갱신/위험도 변화)"
    else:
        title = "⚠️ 고위험 알림"

    lines: list[str] = []
    lines.append(f"*{title}*  `{cve_id}`")
    lines.append(f"- 트리거: {notify_reason} / 변경유형: {change_kind}")
    lines.append(f"- Published: {_fmt(pub)} / Updated: {_fmt(upd)}")
    lines.append(f"- CVSS: {_fmt(cvss_score)} / {cvss_sev}")
    if cvss_vec:
        lines.append(f"- Vector: `{cvss_vec}`")
    lines.append(f"- Attack Vector: {av}")
    lines.append(f"- EPSS: {_fmt(epss)} (pct {_fmt(epss_pct)})")
    lines.append(f"- CISA KEV: {kev} (added {kev_added})")
    if cwe_str:
        lines.append(f"- CWE: {cwe_str}")

    if desc:
        lines.append("\n*설명(원문 일부)*")
        lines.append(desc)

    if refs:
        lines.append("\n*참고(상위 일부)*")
        lines.append(refs_str)

    rule_items = list(top_validated_rules or [])
    if rule_items:
        lines.append(f"\n*검증 통과 룰(복붙 가능, 상위 {min(include_rule_blocks_max, len(rule_items))}개)*")
        for r in rule_items[:include_rule_blocks_max]:
            eng = r.get("engine", "unknown")
            src = r.get("source", "unknown")
            path = r.get("rule_path", "unknown")
            lines.append(f"- `{eng}` / {src} :: {path}")
            lines.append("```")
            lines.append(_rule_snippet(r.get("rule_text", ""), 1200))
            lines.append("```")

        if len(rule_items) > include_rule_blocks_max:
            lines.append(f"_나머지 {len(rule_items)-include_rule_blocks_max}개 검증 통과 룰은 Report 및 rules.zip에서 확인하세요._")

    lines.append("\n" + _engine_registration_guidance().strip())

    lines.append("\n*상세 리포트(30일 링크)*")
    lines.append(report_link)
    if rules_zip_present:
        lines.append("_리포트에는 rules.zip(검증 PASS 룰 전체 번들)도 함께 저장됩니다._")

    lines.append("\n_참고: AI 모델은 웹검색 불가 전제이며, Report의 Evidence Bundle 텍스트가 AI 입력 근거입니다._")
    return "\n".join(lines)
