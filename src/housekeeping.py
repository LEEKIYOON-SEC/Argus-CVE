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
    - Storage report/rules.zip 삭제 + argus.report_artifacts row 삭제
    - pg_cron 없이 "앱 실행 시" daily로 동작
    """
    if not should_run_daily(db):
        return

    bucket = os.getenv("STORAGE_BUCKET", "") or getattr(cfg, "STORAGE_BUCKET", "argus")

    ttl_days = getattr(cfg, "REPORT_TTL_DAYS", None)
    if ttl_days is None:
        try:
            ttl_days = int(os.getenv("REPORT_TTL_DAYS", "30"))
        except Exception:
            ttl_days = 30
    ttl_days = max(1, int(ttl_days))

    buffer_days = int(os.getenv("ARGUS_STORAGE_DELETE_BUFFER_DAYS", "15"))
    buffer_days = max(0, buffer_days)

    cutoff = _utcnow() - timedelta(days=(ttl_days + buffer_days))

    log.info("Housekeeping start: bucket=%s ttl_days=%s buffer_days=%s cutoff=%s", bucket, ttl_days, buffer_days, cutoff.isoformat())

    deleted = 0
    scanned = 0

    # 1) report_artifacts 기반으로 Storage object 삭제
    #    - limit 단위로 반복(대량일 수 있으므로)
    while True:
        rows = db.list_report_artifacts_older_than(cutoff, limit=200)
        if not rows:
            break

        for row in rows:
            scanned += 1
            aid = row.get("id")
            path = row.get("object_path") or ""
            if not path or aid is None:
                # row 깨짐 -> row만 제거 시도
                try:
                    if aid is not None:
                        db.delete_report_artifact_row(int(aid))
                except Exception:
                    pass
                continue

            # Storage delete best-effort
            ok = delete_object(cfg, bucket=bucket, object_path=path)
            if ok:
                deleted += 1

            # 메타 row 삭제(스토리지가 이미 없어도 row는 정리)
            try:
                db.delete_report_artifact_row(int(aid))
            except Exception:
                pass

        # 한번에 너무 오래 걸리지 않게, 200개 단위로 반복

    # 2) CVE state 정리(선택, best-effort)
    #    - 사용자가 요구한 정책(3년 초과 CVE 삭제, 1년 초과 Low 삭제 등)은 다음 세트에서 “정밀하게” 넣는 게 안전.
    #    - 이번 세트는 테이블 스키마 편차를 고려해 기본 OFF.
    if os.getenv("ARGUS_CVE_STATE_CLEANUP", "false").strip().lower() in ("1", "true", "yes", "y", "on"):
        try:
            years3 = _utcnow() - timedelta(days=365 * 3)
            db.delete_cve_state_older_than(years3)
        except Exception:
            pass

    mark_ran(db)
    log.info("Housekeeping done: scanned=%s deleted_objects=%s", scanned, deleted)
