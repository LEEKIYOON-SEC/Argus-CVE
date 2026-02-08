from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup

from .http import http_get, http_head
from .pdf_text import extract_text_from_pdf_bytes

log = logging.getLogger("argus.patch_intel")


@dataclass
class PatchFinding:
    kind: str           # "vendor_advisory" | "release_note" | "patch" | "workaround" | "other"
    title: str
    url: str
    extracted_text: str


def _clip(s: str, n: int) -> str:
    s = (s or "").strip()
    if len(s) <= n:
        return s
    return s[:n] + "…(truncated)"


def _html_to_text(html: bytes, max_chars: int = 7500) -> str:
    """
    HTML → 정규화 텍스트(LLM 입력/Evidence Bundle에 넣기 좋게)
    """
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

    # KB / support 문서도 사실상 권고에 가까움
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

    # PDF는 추출 지원하지만, 성공률 편차가 있으므로 소폭 패널티
    if u.endswith(".pdf"):
        score += 10

    # 바이너리/압축 파일은 텍스트 기반 근거로 쓰기 어렵고 비용만 증가
    if u.endswith((".zip", ".exe", ".msi", ".tar.gz", ".tgz")):
        score += 50

    # 보안 키워드 보너스
    if "psirt" in u:
        score -= 5
    if "security" in u:
        score -= 3
    if "cve" in u:
        score -= 2

    return max(score, 0)


def _is_pdf(url: str, content_type: str) -> bool:
    u = (url or "").lower()
    ct = (content_type or "").lower()
    return ("application/pdf" in ct) or u.endswith(".pdf")


def _get_content_type_best_effort(url: str) -> str:
    """
    HEAD 실패가 꽤 발생하는 현실을 반영해서 best-effort.
    """
    try:
        r = http_head(url, timeout=15, allow_redirects=True)
        return (r.headers.get("Content-Type") or "").lower()
    except Exception:
        return ""


def _extract_pdf_text_from_url(url: str) -> Tuple[bool, str, str]:
    """
    PDF 다운로드→텍스트 레이어 추출
    반환: (ok, title, extracted_text_or_reason)
    """
    try:
        # PDF는 HTML보다 용량이 큰 경우가 있어 max_bytes를 높이되, 무제한은 금지
        pdf_bytes = http_get(
            url,
            timeout=55,
            max_bytes=8 * 1024 * 1024,  # 8MB
            headers={"Accept": "application/pdf"},
        )
    except Exception as e:
        return False, "PDF detected but download failed", f"PDF download failed: {e}"

    res = extract_text_from_pdf_bytes(pdf_bytes, max_pages=10, max_chars=9000)
    if res.ok:
        title = f"PDF extracted ({res.pages} pages, text-layer)"
        return True, title, res.text

    # 텍스트 레이어가 없거나 추출 실패: OCR은 기본 OFF 정책
    return False, "PDF detected but text extraction empty/failed", f"PDF text extraction failed/empty: {res.reason}"


def fetch_patch_findings_from_references(
    references: List[str],
    *,
    max_pages: int = 4,
    per_page_text_limit: int = 7500,
) -> List[PatchFinding]:
    """
    공식 패치/권고를 '가능하면 무조건' 확보하는 수집기.
    - HTML: 본문 텍스트 정규화
    - PDF: 텍스트 레이어 추출(가능한 경우), 스캔 PDF는 실패 사유 기록(OCR 기본 OFF)
    """
    out: List[PatchFinding] = []
    if not references:
        return out

    # 중복 제거 + 우선순위 정렬
    ranked = sorted(list(dict.fromkeys([r for r in references if r])), key=_priority_score)

    for url in ranked[:max_pages]:
        try:
            ctype = _get_content_type_best_effort(url)

            # ✅ PDF 처리
            if _is_pdf(url, ctype):
                ok, title, text_or_reason = _extract_pdf_text_from_url(url)
                out.append(
                    PatchFinding(
                        kind=_classify_url(url),
                        title=title,
                        url=url,
                        extracted_text=text_or_reason,
                    )
                )
                continue

            # ✅ HTML/TEXT 처리
            raw = http_get(
                url,
                timeout=45,
                max_bytes=4 * 1024 * 1024,
                headers={"Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8"},
            )

            text = _html_to_text(raw, max_chars=per_page_text_limit)
            if not text:
                continue

            kind = _classify_url(url)

            # title best-effort: 첫 줄 또는 <title> 기반이 아니라 '추출 텍스트 첫 줄' 사용
            first_line = text.splitlines()[0].strip() if text.splitlines() else url
            title = _clip(first_line, 220)

            out.append(PatchFinding(kind=kind, title=title, url=url, extracted_text=text))

        except Exception as e:
            log.info("patch/advisory fetch failed: %s (%s)", url, e)
            continue

    return out


def build_patch_section_md(findings: List[PatchFinding]) -> str:
    """
    Report용 섹션
    """
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
