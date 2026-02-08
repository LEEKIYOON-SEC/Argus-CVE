from __future__ import annotations

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from .storage_client import delete_object

log = logging.getLogger("argus.housekeeping")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _truthy(s: str) -> bool:
    return (s or "").strip().lower() in ("1", "true", "yes", "y", "on")


def _int(s: Optional[str], default: int) -> int:
    try:
        return int((s or str(default)).strip())
    except Exception:
        return default


def _float(s: Optional[str], default: float) -> float:
    try:
        return float((s or str(default)).strip())
    except Exception:
        return default


def should_run_daily(db, *, key: str = "argus_last_housekeeping_at", min_hours: int = 20) -> bool:
    """
    하루 1회 실행 제어(실제론 20시간 이상 지나면 실행 가능).
    """
    try:
        prev = db.get_setting_text(key)
        if not prev:
            return True
        dt = _parse_iso(prev)
        if not dt:
            return True
        return (_utcnow() - dt) >= timedelta(hours=min_hours)
    except Exception:
        return True


def mark_ran(db, *, key: str = "argus_last_housekeeping_at") -> None:
    try:
        db.set_setting_text(key, _utcnow().isoformat(), description="Last time housekeeping ran (managed by Argus).")
    except Exception:
        pass


def run_housekeeping(cfg, db) -> None:
    """
    정책:
    - Storage: report TTL(기본 30일) + buffer(기본 15일) 지난 객체 삭제
    - DB report_artifacts: cutoff 이전 row 정리
    - DB cve_state: 3년 초과 삭제 + 1년 초과 & Low(CVSS<=3.9) 삭제
    - 전부 argus.settings로 운영 조절 가능
    """
    # enabled gate
    enabled = True
    try:
        v = db.get_setting_text("argus_housekeeping_enabled")
        if v is not None:
            enabled = _truthy(v)
    except Exception:
        pass
    if not enabled:
        return

    if not should_run_daily(db):
        return

    bucket = os.getenv("STORAGE_BUCKET", "") or getattr(cfg, "STORAGE_BUCKET", "argus")

    # TTL days (Signed URL 기간과 동일하게 운용하는 게 일관성 있음)
    ttl_days = getattr(cfg, "REPORT_TTL_DAYS", None)
    if ttl_days is None:
        try:
            ttl_days = int(os.getenv("REPORT_TTL_DAYS", "30"))
        except Exception:
            ttl_days = 30
    ttl_days = max(1, int(ttl_days))

    # buffer days from settings
    buffer_days = 15
    try:
        v = db.get_setting_text("argus_storage_delete_buffer_days")
        if v is not None:
            buffer_days = _int(v, 15)
    except Exception:
        pass
    buffer_days = max(0, int(buffer_days))

    cutoff = _utcnow() - timedelta(days=(ttl_days + buffer_days))

    log.info(
        "Housekeeping start: bucket=%s ttl_days=%s buffer_days=%s cutoff=%s",
        bucket, ttl_days, buffer_days, cutoff.isoformat(),
    )

    # 1) Storage + report_artifacts cleanup
    deleted_objects = 0
    scanned_rows = 0

    while True:
        try:
            rows = db.list_report_artifacts_older_than(cutoff, limit=200)
        except Exception:
            rows = []

        if not rows:
            break

        for row in rows:
            scanned_rows += 1
            aid = row.get("id")
            path = (row.get("object_path") or "").strip()

            # row만 깨진 경우 -> row 삭제 시도
            if not path or aid is None:
                try:
                    if aid is not None:
                        db.delete_report_artifact_row(int(aid))
                except Exception:
                    pass
                continue

            ok = delete_object(cfg, bucket=bucket, object_path=path)
            if ok:
                deleted_objects += 1

            # 메타 row 정리(스토리지가 이미 없어도 row는 제거)
            try:
                db.delete_report_artifact_row(int(aid))
            except Exception:
                pass

    # 2) cve_state cleanup 정책(3년 + low 1년)
    cve_cleanup_enabled = True
    try:
        v = db.get_setting_text("argus_cve_state_delete_enabled")
        if v is not None:
            cve_cleanup_enabled = _truthy(v)
    except Exception:
        pass

    if cve_cleanup_enabled:
        # 3년 초과
        days_3y = 1095
        try:
            v = db.get_setting_text("argus_cve_state_delete_older_than_days")
            if v is not None:
                days_3y = _int(v, 1095)
        except Exception:
            pass

        # low 1년 초과
        low_days = 365
        try:
            v = db.get_setting_text("argus_cve_state_delete_low_older_than_days")
            if v is not None:
                low_days = _int(v, 365)
        except Exception:
            pass

        low_cvss_max = 3.9
        try:
            v = db.get_setting_text("argus_cve_state_low_cvss_max")
            if v is not None:
                low_cvss_max = _float(v, 3.9)
        except Exception:
            pass

        # best-effort (테이블/컬럼 없으면 내부에서 무시됨)
        try:
            db.delete_cve_state_older_than_days(days_3y)
        except Exception:
            pass
        try:
            db.delete_cve_state_low_older_than_days(low_days, low_cvss_max=low_cvss_max)
        except Exception:
            pass

    mark_ran(db)
    log.info(
        "Housekeeping done: scanned_report_artifacts=%s deleted_storage_objects=%s cve_cleanup_enabled=%s",
        scanned_rows, deleted_objects, cve_cleanup_enabled
    )
