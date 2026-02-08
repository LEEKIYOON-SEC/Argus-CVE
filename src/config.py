from __future__ import annotations

import os
from dataclasses import dataclass


def _req(name: str) -> str:
    v = os.getenv(name, "").strip()
    if not v:
        raise RuntimeError(f"Missing required env: {name}")
    return v


def _opt(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name, "true" if default else "false").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)).strip())
    except Exception:
        return default


@dataclass
class Config:
    # === Secrets ===
    GH_TOKEN: str
    SLACK_WEBHOOK_URL: str
    SUPABASE_URL: str
    SUPABASE_KEY: str
    VULNCHECK_API_KEY: str
    GROQ_API_KEY: str

    # === Source policy ===
    CVE_SOURCE: str = "cve.org"
    CVE_CVEORG_STATE: str = "PUBLISHED"   # PUBLISHED만 사용(요구사항)
    CVE_EXCLUDE_REJECTED: bool = True     # REJECTED 제외(요구사항)

    # === EPSS policy (요구사항 고정값) ===
    # EPSS ≥ 0.1 : 즉시 알림
    # 0.01 ≤ EPSS < 0.1 : CVSS High 이상일 경우 알림
    EPSS_IMMEDIATE: float = 0.1
    EPSS_CONDITIONAL: float = 0.01

    # === Storage / Slack ===
    USE_STORAGE: bool = True
    STORAGE_BUCKET: str = "argus"
    REPORT_TTL_DAYS: int = 30

    # === Runtime tuning (DB settings가 있으면 runtime_overrides에서 덮어씀) ===
    ARGUS_GH_SNIPPET_FETCH_MAX: int = 2
    ARGUS_GH_RULE_CANDIDATES_MAX: int = 4
    ARGUS_SLACK_RULE_BLOCKS_MAX: int = 3

    # PDF extraction safety (DB settings가 있으면 덮어씀)
    ARGUS_PDF_MAX_PAGES: int = 8
    ARGUS_PDF_MAX_CHARS: int = 7000


def load_config() -> Config:
    cfg = Config(
        GH_TOKEN=_req("GH_TOKEN"),
        SLACK_WEBHOOK_URL=_req("SLACK_WEBHOOK_URL"),
        SUPABASE_URL=_req("SUPABASE_URL"),
        SUPABASE_KEY=_req("SUPABASE_KEY"),
        VULNCHECK_API_KEY=_req("VULNCHECK_API_KEY"),
        GROQ_API_KEY=_req("GROQ_API_KEY"),
    )

    # storage 옵션(워크플로우에서 바꿀 수 있음)
    cfg.USE_STORAGE = _bool("USE_STORAGE", True)
    cfg.STORAGE_BUCKET = _opt("STORAGE_BUCKET", "argus") or "argus"
    cfg.REPORT_TTL_DAYS = max(1, _int("REPORT_TTL_DAYS", 30))

    # 튜닝 env(필요 시)
    cfg.ARGUS_GH_SNIPPET_FETCH_MAX = max(0, _int("ARGUS_GH_SNIPPET_FETCH_MAX", cfg.ARGUS_GH_SNIPPET_FETCH_MAX))
    cfg.ARGUS_GH_RULE_CANDIDATES_MAX = max(0, _int("ARGUS_GH_RULE_CANDIDATES_MAX", cfg.ARGUS_GH_RULE_CANDIDATES_MAX))
    cfg.ARGUS_SLACK_RULE_BLOCKS_MAX = max(0, _int("ARGUS_SLACK_RULE_BLOCKS_MAX", cfg.ARGUS_SLACK_RULE_BLOCKS_MAX))

    # EPSS는 기본값을 cfg에 두되, 운영 중에는 DB settings로 덮어쓰는 구조(runtime_overrides)
    # 여기서는 env로도 임시 오버라이드 가능하게 해둠(선택)
    cfg.EPSS_IMMEDIATE = _float("EPSS_IMMEDIATE", cfg.EPSS_IMMEDIATE)
    cfg.EPSS_CONDITIONAL = _float("EPSS_CONDITIONAL", cfg.EPSS_CONDITIONAL)

    # PDF safety
    cfg.ARGUS_PDF_MAX_PAGES = max(1, _int("ARGUS_PDF_MAX_PAGES", cfg.ARGUS_PDF_MAX_PAGES))
    cfg.ARGUS_PDF_MAX_CHARS = max(500, _int("ARGUS_PDF_MAX_CHARS", cfg.ARGUS_PDF_MAX_CHARS))

    return cfg
