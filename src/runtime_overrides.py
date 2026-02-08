from __future__ import annotations

import os
import logging
from typing import Any, Optional

from .settings_store import get_setting_text

log = logging.getLogger("argus.runtime_overrides")


def _get_db_text(cfg, key: str) -> Optional[str]:
    try:
        v = get_setting_text(cfg, key)
        if v is None:
            return None
        v = v.strip()
        return v if v != "" else None
    except Exception as e:
        log.info("settings_store error for key=%s: %s", key, e)
        return None


def _cast_int(s: str) -> Optional[int]:
    try:
        return int(s.strip())
    except Exception:
        return None


def _cast_float(s: str) -> Optional[float]:
    try:
        return float(s.strip())
    except Exception:
        return None


def _cast_bool(s: str) -> Optional[bool]:
    t = s.strip().lower()
    if t in ("1", "true", "yes", "y", "on"):
        return True
    if t in ("0", "false", "no", "n", "off"):
        return False
    return None


def _setattr_safe(cfg: Any, attr: str, value: Any) -> None:
    try:
        setattr(cfg, attr, value)
    except Exception as e:
        log.info("setattr failed cfg.%s=%r: %s", attr, value, e)


def _setenv_safe(key: str, value: str) -> None:
    try:
        os.environ[key] = str(value)
    except Exception:
        pass


def apply_runtime_overrides(cfg) -> None:
    """
    Supabase(argus.settings) 값을 런타임에 cfg + env로 주입.
    - cfg: 기존 코드가 cfg.* 참조할 때 정책이 반영
    - env: rules_bundle처럼 env를 읽는 모듈도 DB 정책을 따르게 함(구조 변경 최소화)
    """

    # -------------------------
    # GitHub OSINT tuning
    # -------------------------
    v = _get_db_text(cfg, "argus_gh_snippet_fetch_max")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_GH_SNIPPET_FETCH_MAX", max(0, vi))
            _setenv_safe("ARGUS_GH_SNIPPET_FETCH_MAX", str(max(0, vi)))

    v = _get_db_text(cfg, "argus_gh_rule_candidates_max")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_GH_RULE_CANDIDATES_MAX", max(0, vi))
            _setenv_safe("ARGUS_GH_RULE_CANDIDATES_MAX", str(max(0, vi)))

    # -------------------------
    # EPSS policy (DB override)
    # -------------------------
    v = _get_db_text(cfg, "argus_epss_immediate")
    if v is not None:
        vf = _cast_float(v)
        if vf is not None:
            _setattr_safe(cfg, "EPSS_IMMEDIATE", vf)

    v = _get_db_text(cfg, "argus_epss_conditional")
    if v is not None:
        vf = _cast_float(v)
        if vf is not None:
            _setattr_safe(cfg, "EPSS_CONDITIONAL", vf)

    # -------------------------
    # Slack rule blocks cap
    # -------------------------
    v = _get_db_text(cfg, "argus_slack_rule_blocks_max")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_SLACK_RULE_BLOCKS_MAX", max(0, vi))
            _setenv_safe("ARGUS_SLACK_RULE_BLOCKS_MAX", str(max(0, vi)))

    # -------------------------
    # PDF extraction caps (safety)
    # -------------------------
    v = _get_db_text(cfg, "argus_pdf_max_pages")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_PDF_MAX_PAGES", max(1, vi))
            _setenv_safe("ARGUS_PDF_MAX_PAGES", str(max(1, vi)))

    v = _get_db_text(cfg, "argus_pdf_max_chars")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_PDF_MAX_CHARS", max(500, vi))
            _setenv_safe("ARGUS_PDF_MAX_CHARS", str(max(500, vi)))

    # -------------------------
    # Report/ZIP size caps (DB -> cfg/env)
    # report_store는 DB를 직접 읽지만, env도 맞춰둠(일관성)
    # -------------------------
    v = _get_db_text(cfg, "argus_report_max_bytes")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setenv_safe("ARGUS_REPORT_MAX_BYTES", str(max(10_000, vi)))

    v = _get_db_text(cfg, "argus_rules_zip_max_bytes")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setenv_safe("ARGUS_RULES_ZIP_MAX_BYTES", str(max(50_000, vi)))

    # -------------------------
    # ZIP bundling caps (THIS makes rules_bundle follow DB policy)
    # rules_bundle reads:
    #   ARGUS_RULE_TEXT_MAX_BYTES_PER_RULE
    #   ARGUS_ZIP_MAX_RULES_TOTAL
    #   ARGUS_ZIP_MAX_RULES_PER_ENGINE
    # -------------------------
    v = _get_db_text(cfg, "argus_rule_text_max_bytes_per_rule")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setenv_safe("ARGUS_RULE_TEXT_MAX_BYTES_PER_RULE", str(max(1000, vi)))

    v = _get_db_text(cfg, "argus_zip_max_rules_total")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setenv_safe("ARGUS_ZIP_MAX_RULES_TOTAL", str(max(10, vi)))

    v = _get_db_text(cfg, "argus_zip_max_rules_per_engine")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setenv_safe("ARGUS_ZIP_MAX_RULES_PER_ENGINE", str(max(5, vi)))

    # -------------------------
    # Storage TTL (Signed URL expiration)
    # -------------------------
    v = _get_db_text(cfg, "argus_report_ttl_days")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "REPORT_TTL_DAYS", max(1, vi))
            _setenv_safe("REPORT_TTL_DAYS", str(max(1, vi)))

    log.info(
        "Runtime overrides applied (cfg/env synced). "
        "GH_SNIPPET=%s GH_RULE_MAX=%s SLACK_RULE_BLOCKS=%s TTL_DAYS=%s ZIP_CAPS(per_rule=%s total=%s per_engine=%s)",
        getattr(cfg, "ARGUS_GH_SNIPPET_FETCH_MAX", None),
        getattr(cfg, "ARGUS_GH_RULE_CANDIDATES_MAX", None),
        getattr(cfg, "ARGUS_SLACK_RULE_BLOCKS_MAX", None),
        getattr(cfg, "REPORT_TTL_DAYS", None),
        os.getenv("ARGUS_RULE_TEXT_MAX_BYTES_PER_RULE"),
        os.getenv("ARGUS_ZIP_MAX_RULES_TOTAL"),
        os.getenv("ARGUS_ZIP_MAX_RULES_PER_ENGINE"),
    )
