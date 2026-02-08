from __future__ import annotations

import re
from typing import List, Optional

from .patch_intel import PatchFinding
from .vulncheck_intel import VulnCheckFinding
from .github_osint import GitHubFinding


def _norm(text: str) -> str:
    t = (text or "").strip()
    t = re.sub(r"[ \t]{2,}", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def _clip(text: str, max_chars: int) -> str:
    t = _norm(text)
    if len(t) <= max_chars:
        return t
    return t[:max_chars] + "\n...(truncated)"


def build_evidence_bundle_text(
    *,
    cfg,
    cve: dict,
    patch_findings: List[PatchFinding],
    official_rules_summary_lines: List[str],
    vulncheck_findings: Optional[List[VulnCheckFinding]] = None,
    github_findings: Optional[List[GitHubFinding]] = None,
    ai_rule_generation_notes: Optional[str] = None,
    max_total_chars: int = 24000,
) -> str:
    """
    Llama-4-maverick 웹검색 불가 전제를 강제하기 위한 Evidence Bundle(정규화 텍스트) 생성.
    - URL이 아니라, 우리가 가져온 텍스트를 중심으로 구성
    - OSINT/VulnCheck/GitHub 발견을 '텍스트 근거'로 삽입하여 룰 정밀도를 상승
    """
    parts: List[str] = []

    # 1) 정책/판정 기준(고정)
    parts.append("## Policy")
    parts.append(f"- EPSS >= {cfg.EPSS_IMMEDIATE}: immediate alert")
    parts.append(f"- {cfg.EPSS_CONDITIONAL} <= EPSS < {cfg.EPSS_IMMEDIATE}: alert only if CVSS High+")
    parts.append("- Exclude CVE state=REJECTED; include PUBLISHED only (datePublished exists).")
    parts.append("- Sigma MUST be provided.")
    parts.append("- Network vs Host rules are routed by attack vector and evidence (minimize false positives).")
    parts.append("")

    # 2) CVE 핵심 메타
    parts.append("## CVE Core")
    parts.append(f"- CVE: {cve.get('cve_id')}")
    parts.append(f"- Published: {cve.get('date_published')}")
    parts.append(f"- Updated: {cve.get('date_updated')}")
    parts.append(f"- CVSS: {cve.get('cvss_score')} / {cve.get('cvss_severity')}")
    parts.append(f"- Vector: {cve.get('cvss_vector')}")
    parts.append(f"- Attack Vector: {cve.get('attack_vector')}")
    parts.append(f"- CWE: {', '.join(cve.get('cwe_ids') or [])}")
    parts.append(f"- EPSS: {cve.get('epss_score')} (pct {cve.get('epss_percentile')})")
    parts.append(f"- CISA KEV: {bool(cve.get('is_cisa_kev') or False)} (added {cve.get('kev_added_date')})")
    parts.append("")

    # 3) CVE 설명(원문)
    parts.append("## Description (EN)")
    parts.append(_clip(cve.get("description_en") or "", 7000))
    parts.append("")

    # 4) KEV 컨텍스트
    kev_notes = cve.get("kev_notes")
    kev_action = cve.get("kev_required_action")
    kev_ransom = cve.get("kev_ransomware")
    if kev_notes or kev_action or kev_ransom is not None:
        parts.append("## CISA KEV Context (if any)")
        if kev_ransom is not None:
            parts.append(f"- knownRansomwareCampaignUse: {kev_ransom}")
        if kev_action:
            parts.append("### requiredAction")
            parts.append(_clip(str(kev_action), 3000))
        if kev_notes:
            parts.append("### notes")
            parts.append(_clip(str(kev_notes), 3000))
        parts.append("")

    # 5) 공식 룰 발견 요약
    parts.append("## Official/Public Rules Discovery Summary")
    if official_rules_summary_lines:
        parts.extend(official_rules_summary_lines[:200])
    else:
        parts.append("- No official/public rules matched in this run.")
    parts.append("")

    # 6) VulnCheck OSINT(텍스트 근거)
    parts.append("## VulnCheck OSINT (Normalized)")
    vfs = vulncheck_findings or []
    if not vfs:
        parts.append("- No VulnCheck findings in this run.")
    else:
        for i, f in enumerate(vfs[:3], 1):
            parts.append(f"### VulnCheck {i} ({f.kind})")
            parts.append(_clip(f.evidence, 6000))
            parts.append("")
    parts.append("")

    # 7) GitHub OSINT(발견 근거)
    parts.append("## GitHub OSINT (Discovery, Normalized)")
    gfs = github_findings or []
    if not gfs:
        parts.append("- No GitHub findings in this run (or GH_TOKEN not set).")
    else:
        for i, f in enumerate(gfs[:8], 1):
            parts.append(f"### GitHub {i} ({f.kind}) {f.title}")
            parts.append(_clip(f.evidence, 2500))
            parts.append("")
    parts.append("")

    # 8) 패치/권고 텍스트
    parts.append("## Vendor Patch / Advisory (Normalized Text)")
    if not patch_findings:
        parts.append("- No patch/advisory text extracted in this run (JS rendering/auth may be required).")
    else:
        for i, f in enumerate(patch_findings[:4], 1):
            parts.append(f"### Patch Source {i} [{f.kind}] {f.title}")
            parts.append(f"- URL: {f.url}")
            parts.append("")
            parts.append(_clip(f.extracted_text, 6500))
            parts.append("")
    parts.append("")

    # 9) AI 룰 생성 노트(있으면)
    if ai_rule_generation_notes:
        parts.append("## AI Rule Generation Notes")
        parts.append(_clip(ai_rule_generation_notes, 3500))
        parts.append("")

    bundle = _norm("\n".join(parts))
    if len(bundle) > max_total_chars:
        bundle = bundle[:max_total_chars] + "\n...(bundle truncated)"
    return bundle + "\n"
