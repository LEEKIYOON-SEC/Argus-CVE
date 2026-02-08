from __future__ import annotations

import os
from dataclasses import dataclass


def _req(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing env: {name}")
    return v


def _opt(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v is not None and v != "" else default


def _opt_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _opt_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    return float(v)


def _opt_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    return int(v)


@dataclass(frozen=True)
class Config:
    # Secrets
    GH_TOKEN: str
    SLACK_WEBHOOK_URL: str
    SUPABASE_URL: str
    SUPABASE_KEY: str  # service_role 권장/전제
    VULNCHECK_API_KEY: str
    GROQ_API_KEY: str

    # Policies
    EPSS_IMMEDIATE: float          # >= 0.1 즉시
    EPSS_CONDITIONAL: float        # >= 0.01 and <0.1 인 경우 조건부
    REPORT_TTL_DAYS: int           # Slack 링크(Report Signed URL) 유효기간(일)
    STORAGE_BUCKET: str
    USE_STORAGE: bool

    # Retention policy (DB/Storage housekeeping에 사용)
    RETENTION_YEARS: int
    LOW_RETENTION_YEARS: int
    LOW_CVSS_MAX: float
    LOW_EPSS_MAX: float

    # ET Open 룰셋 (Suricata + Snort2)
    ET_OPEN_SURICATA_URL: str
    ET_OPEN_SNORT_URL: str

    # Optional: Snort community zip direct (안정 URL이 있으면 설정)
    SNORT_COMMUNITY_ZIP_URL: str | None

    # GitHub Search API 사용 시(공개 룰 보강 용도) - 향후 모듈에서 사용
    GH_SEARCH_ENABLE: bool


def load_config() -> Config:
    """
    GitHub Actions env/secrets 기준으로 로딩.
    """
    return Config(
        GH_TOKEN=_req("GH_TOKEN"),
        SLACK_WEBHOOK_URL=_req("SLACK_WEBHOOK_URL"),
        SUPABASE_URL=_req("SUPABASE_URL"),
        SUPABASE_KEY=_req("SUPABASE_KEY"),
        VULNCHECK_API_KEY=_req("VULNCHECK_API_KEY"),
        GROQ_API_KEY=_req("GROQ_API_KEY"),

        EPSS_IMMEDIATE=_opt_float("ARGUS_EPSS_IMMEDIATE", 0.1),
        EPSS_CONDITIONAL=_opt_float("ARGUS_EPSS_CONDITIONAL", 0.01),
        REPORT_TTL_DAYS=_opt_int("ARGUS_REPORT_TTL_DAYS", 30),

        STORAGE_BUCKET=_opt("ARGUS_STORAGE_BUCKET", "argus-reports") or "argus-reports",
        USE_STORAGE=_opt_bool("ARGUS_USE_STORAGE", True),

        RETENTION_YEARS=_opt_int("ARGUS_RETENTION_YEARS", 3),
        LOW_RETENTION_YEARS=_opt_int("ARGUS_LOW_RETENTION_YEARS", 1),
        LOW_CVSS_MAX=_opt_float("ARGUS_LOW_CVSS_MAX", 4.0),
        LOW_EPSS_MAX=_opt_float("ARGUS_LOW_EPSS_MAX", 0.01),

        # ET Open: 기본 경로(운영 시 버전 올려도 됨)
        ET_OPEN_SURICATA_URL=_opt(
            "ARGUS_ET_OPEN_SURICATA_URL",
            "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
        ) or "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
        ET_OPEN_SNORT_URL=_opt(
            "ARGUS_ET_OPEN_SNORT_URL",
            "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",
        ) or "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",

        SNORT_COMMUNITY_ZIP_URL=_opt("ARGUS_SNORT_COMMUNITY_ZIP_URL", None),
        GH_SEARCH_ENABLE=_opt_bool("ARGUS_GH_SEARCH_ENABLE", True),
    )
