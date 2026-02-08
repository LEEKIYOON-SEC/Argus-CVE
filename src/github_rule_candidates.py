from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

from .github_osint import GitHubFinding
from .rule_validation import validate_by_engine


def _default_allowlist() -> List[str]:
    # “공신력 있는 공개 룰” 중심 (기본값)
    return [
        "SigmaHQ/sigma",
        "Neo23x0/sigma",
        "Neo23x0/signature-base",
        "Yara-Rules/rules",
        "OISF/suricata",
    ]


def _get_allowlist(cfg) -> List[str]:
    raw = getattr(cfg, "GITHUB_TRUSTED_REPOS", None) or os.getenv("GITHUB_TRUSTED_REPOS", "")
    raw = (raw or "").strip()
    if not raw:
        return _default_allowlist()
    return [x.strip() for x in raw.split(",") if x.strip()]


def _extract_repo_full_name_from_title(title: str) -> str:
    # title: "owner/repo/path"
    if not title:
        return ""
    parts = title.split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return ""


def _guess_engine_from_path(title: str) -> str:
    t = (title or "").lower()
    # sigma
    if t.endswith((".yml", ".yaml")) and ("sigma" in t or "/rules/" in t or "/detection/" in t):
        return "sigma"
    # yara
    if t.endswith((".yar", ".yara")):
        return "yara"
    # suricata/snort 공통: .rules
    if t.endswith(".rules"):
        # GitHub 상에서는 suricata/snort 폴더 힌트가 있는 경우가 많음
        if "/suricata/" in t or "suricata" in t:
            return "suricata"
        if "/snort3/" in t or "snort3" in t:
            return "snort3"
        if "/snort/" in t or "snort" in t:
            return "snort2"
        # 애매하면 suricata로 두지 말고 "snort2"도 아님 → 기본은 suricata로 하지 않고 'suricata' 우선 검증 후 실패하면 snort2로 fallback 하는 전략을 main에서 쓸 수도 있음
        return "suricata"
    return ""


def _extract_snippet_block(evidence: str) -> str:
    """
    github_osint.enrich_code_findings_with_snippets()가 evidence에 넣어주는
    ``` ... ``` 블록을 파싱해 룰 텍스트 후보로 사용.
    """
    if not evidence:
        return ""
    m = re.search(r"```(?:\w+)?\n(.*?)\n```", evidence, flags=re.DOTALL)
    if not m:
        return ""
    return (m.group(1) or "").strip()


def fetch_trusted_github_rule_candidates(
    cfg,
    *,
    cve_id: str,
    github_findings: List[GitHubFinding],
    max_rules: int = 4,
) -> List[Dict]:
    """
    반환은 official_hits와 동일한 dict 스키마로 맞춤:
    - engine, source, rule_path, rule_text, reference
    """
    allow = set([x.lower() for x in _get_allowlist(cfg)])
    out: List[Dict] = []

    for f in github_findings:
        if f.kind != "code":
            continue

        repo = _extract_repo_full_name_from_title(f.title).lower()
        if not repo:
            continue
        if repo not in allow:
            # 공신력 기준: allowlist 밖은 공식 룰 후보로 편입하지 않음(노이즈/리스크 방지)
            continue

        engine = _guess_engine_from_path(f.title)
        snippet = _extract_snippet_block(f.evidence)
        if not snippet:
            continue

        # 엔진이 명확하지 않으면 편입하지 않음(모호성 제거)
        if engine not in ("sigma", "yara", "suricata", "snort2", "snort3"):
            continue

        # ✅ 검증(엔진 바이너리/cli 기반)
        vr = validate_by_engine(engine, snippet)
        if not vr.ok:
            # 검증 실패한 GitHub 룰은 "공식 룰 후보"로 편입하지 않음
            continue

        out.append(
            {
                "engine": engine,
                "source": "github_trusted",
                "rule_path": f.title,  # owner/repo/path 형태로 기록
                "rule_text": snippet,
                "reference": f.raw_url or f.api_url or "",
            }
        )

        if len(out) >= max_rules:
            break

    return out
