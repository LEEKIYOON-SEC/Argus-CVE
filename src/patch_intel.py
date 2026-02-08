from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup

from .http import http_get, http_head

log = logging.getLogger("argus.patch_intel")


@dataclass
class PatchFinding:
    kind: str           # "vendor_advisory" | "release_note" | "patch" | "workaround" | "other"
    title: str
    url: str
    extracted_text: str


def _html_to_text(html: bytes, max_chars: int = 6500) -> str:
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]{2,}", " ", text)
        text = text.strip()
        if len(text) > max_chars:
            text = text[:max_chars] + "\n...(truncated)"
        return text
    except Exception:
        return ""


def _classify_url(url: str) -> str:
    u = (url or "").lower()

    # 보안권고 우선
    if any(k in u for k in ["security", "advisory", "bulletin", "alert", "/cve", "psirt"]):
        return "vendor_advisory"

    # KB / 고정 문서
    if any(k in u for k in ["kb", "knowledgebase", "support", "documentation", "docs"]):
        return "vendor_advisory"

    # 릴리즈/체인지로그
    if any(k in u for k in ["release", "releases", "changelog", "notes", "version", "upgrade"]):
        return "release_note"

    # 패치/다운로드
    if any(k in u for k in ["patch", "download", "fix", "hotfix"]):
        return "patch"

    # 완화/워크어라운드
    if any(k in u for k in ["workaround", "mitigation", "hardening"]):
        return "workaround"

    return "other"


def _priority_score(url: str) -> int:
    """
    낮을수록 높은 우선순위.
    """
    u = (url or "").lower()
    kind = _classify_url(url)

    score = 50
    if kind == "vendor_advisory":
        score = 0
    elif kind == "release_note":
        score = 10
    elif kind == "patch":
        score = 15
    elif kind == "workaround":
        score = 20
    else:
        score = 40

    # 파일형식 패널티(HTML 우선)
    if u.endswith(".pdf"):
        score += 30
    if u.endswith((".zip", ".exe", ".msi", ".tar.gz")):
        score += 40

    # 보안 키워드 보너스
    if "psirt" in u:
        score -= 5
    if "security" in u:
        score -= 3
    if "cve" in u:
        score -= 2

    return max(score, 0)


def fetch_patch_findings_from_references(
    references: List[str],
    *,
    max_pages: int = 4,
    per_page_text_limit: int = 6500,
) -> List[PatchFinding]:
    """
    공식 패치/권고를 '가능하면 무조건' 확보하기 위한 1차 수집기(성공률 보강).
    - max_pages는 운영 안정성/비용 0/레이트 제한을 위해 유지
    """
    out: List[PatchFinding] = []
    if not references:
        return out

    ranked = sorted(list(dict.fromkeys(references)), key=_priority_score)  # 중복 제거 + 우선순위 정렬

    for url in ranked[:max_pages]:
        try:
            # 먼저 HEAD로 콘텐츠 타입 확인(가능하면)
            ctype = ""
            try:
                h = http_head(url, timeout=15)
                ctype = (h.headers.get("Content-Type") or "").lower()
            except Exception:
                ctype = ""

            # PDF/바이너리는 현재 단계에서 텍스트 추출하지 않음(추후 확장)
            if "application/pdf" in ctype or url.lower().endswith(".pdf"):
                out.append(
                    PatchFinding(
                        kind=_classify_url(url),
                        title="PDF detected (text extraction skipped in current build)",
                        url=url,
                        extracted_text="PDF content detected. Text extraction is not enabled in current build. Consider adding a PDF text extraction step if needed.",
                    )
                )
                continue

            raw = http_get(url, timeout=40, headers={"Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8"})
            text = _html_to_text(raw, max_chars=per_page_text_limit)
            if not text:
                continue

            kind = _classify_url(url)
            title = text.splitlines()[0][:200] if text.splitlines() else url

            out.append(PatchFinding(kind=kind, title=title, url=url, extracted_text=text))

        except Exception as e:
            log.info("patch page fetch failed: %s (%s)", url, e)
            continue

    return out


def build_patch_section_md(findings: List[PatchFinding]) -> str:
    lines: List[str] = []
    lines.append("## 7) Vendor Patch / Advisory (Best-effort)")
    if not findings:
        lines.append("- No patch/advisory text could be extracted from references in this run.")
        lines.append("- NOTE: Some vendor pages require JS rendering or authentication.")
        return "\n".join(lines).strip() + "\n"

    for i, f in enumerate(findings, 1):
        lines.append(f"### 7.{i} {f.kind} :: {f.title}")
        lines.append(f"- URL: {f.url}")
        lines.append("")
        lines.append("Extracted (normalized) text:")
        lines.append("```")
        lines.append(f.extracted_text)
        lines.append("```")
        lines.append("")
    return "\n".join(lines).strip() + "\n"
