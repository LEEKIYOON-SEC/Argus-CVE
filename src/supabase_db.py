from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from supabase import create_client, Client

log = logging.getLogger("argus.supabase")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SupabaseDB:
    """
    schema.sql 기준 테이블/뷰 접근 래퍼.
    - public.cve_state
    - public.report_objects
    - public.run_log
    - public.v_expired_report_objects (view)
    """

    def __init__(self, url: str, key: str):
        self.url = url
        self.key = key
        self.sb: Client = create_client(url, key)

    # -------------------------
    # Run log
    # -------------------------
    def log_run(self, kind: str, ok: bool, summary: str | None = None) -> None:
        try:
            self.sb.table("run_log").insert(
                {"kind": kind, "ok": ok, "summary": summary or ""}
            ).execute()
        except Exception as e:
            log.warning("run_log insert failed: %s", e)

    # -------------------------
    # Poll time (last run time)
    # - 별도 테이블을 만들지 않고 run_log의 RUN 최신값을 사용
    # -------------------------
    def get_last_poll_time(self, default_minutes: int = 60) -> datetime:
        """
        마지막 RUN 시간.
        - 최초 실행이면 now - default_minutes
        """
        try:
            res = (
                self.sb.table("run_log")
                .select("run_at")
                .eq("kind", "RUN")
                .order("run_at", desc=True)
                .limit(1)
                .execute()
            )
            rows = res.data or []
            if not rows:
                return _utcnow() - timedelta(minutes=default_minutes)

            # Supabase는 ISO string 반환
            s = rows[0]["run_at"]
            # fromisoformat은 'Z'가 있으면 처리 불가인 버전이 있어 replace
            if isinstance(s, str):
                s2 = s.replace("Z", "+00:00")
                return datetime.fromisoformat(s2)
            return _utcnow() - timedelta(minutes=default_minutes)
        except Exception:
            return _utcnow() - timedelta(minutes=default_minutes)

    def set_last_poll_time(self, ts: datetime) -> None:
        # set은 run_log에 기록하는 것으로 대체(추적성 확보)
        self.log_run("RUN", True, f"poll_time={ts.isoformat()}")

    # -------------------------
    # CVE state
    # -------------------------
    def get_cve_state(self, cve_id: str) -> Optional[dict[str, Any]]:
        try:
            res = self.sb.table("cve_state").select("*").eq("cve_id", cve_id).limit(1).execute()
            rows = res.data or []
            return rows[0] if rows else None
        except Exception as e:
            log.warning("get_cve_state failed: %s", e)
            return None

    def upsert_cve_state(
        self,
        cve: dict[str, Any],
        *,
        last_seen_at: datetime,
        last_notified_at: datetime | None = None,
        last_notified_type: str | None = None,
        last_notify_reason: str | None = None,
        last_payload_hash: str | None = None,
        last_rule_status: str | None = None,
        last_official_rule_fingerprint: str | None = None,
        last_ai_rule_fingerprint: str | None = None,
        last_patch_fingerprint: str | None = None,
        last_report_path: str | None = None,
        last_rules_zip_path: str | None = None,
    ) -> None:
        """
        schema.sql 컬럼에 맞춘 업서트.
        cve dict는 상위 파이프라인에서 표준화된 키를 갖는 것을 전제로 함.
        """
        row: dict[str, Any] = {
            "cve_id": cve["cve_id"],
            "last_seen_at": last_seen_at.isoformat(),
            "published_date": cve.get("published_date"),
            "last_modified_date": cve.get("last_modified_date"),
            "cvss_score": cve.get("cvss_score"),
            "cvss_severity": cve.get("cvss_severity"),
            "cvss_vector": cve.get("cvss_vector"),
            "attack_vector": cve.get("attack_vector"),
            "cwe_ids": cve.get("cwe_ids") or [],
            "cce_ids": cve.get("cce_ids") or [],
            "epss_score": cve.get("epss_score"),
            "epss_percentile": cve.get("epss_percentile"),
            "is_cisa_kev": bool(cve.get("is_cisa_kev") or False),
            "kev_added_date": cve.get("kev_added_date"),
            "vulncheck_weaponized": cve.get("vulncheck_weaponized"),
            "vulncheck_evidence": cve.get("vulncheck_evidence"),
        }

        # optional fields
        if last_notified_at is not None:
            row["last_notified_at"] = last_notified_at.isoformat()
        if last_notified_type is not None:
            row["last_notified_type"] = last_notified_type
        if last_notify_reason is not None:
            row["last_notify_reason"] = last_notify_reason
        if last_payload_hash is not None:
            row["last_payload_hash"] = last_payload_hash

        if last_rule_status is not None:
            row["last_rule_status"] = last_rule_status
        if last_official_rule_fingerprint is not None:
            row["last_official_rule_fingerprint"] = last_official_rule_fingerprint
        if last_ai_rule_fingerprint is not None:
            row["last_ai_rule_fingerprint"] = last_ai_rule_fingerprint
        if last_patch_fingerprint is not None:
            row["last_patch_fingerprint"] = last_patch_fingerprint

        if last_report_path is not None:
            row["last_report_path"] = last_report_path
        if last_rules_zip_path is not None:
            row["last_rules_zip_path"] = last_rules_zip_path

        try:
            self.sb.table("cve_state").upsert(row).execute()
        except Exception as e:
            log.error("upsert_cve_state failed: %s", e)
            raise

    # -------------------------
    # Report objects
    # -------------------------
    def insert_report_object(
        self,
        *,
        cve_id: str,
        alert_type: str,
        primary_reason: str,
        report_path: str,
        rules_zip_path: str | None,
        content_hash: str,
        report_sha256: str,
        rules_sha256: str | None,
        retention_until: datetime,
        kev_listed: bool,
        signed_url_expiry_seconds: int = 2592000,
    ) -> None:
        row = {
            "cve_id": cve_id,
            "alert_type": alert_type,
            "primary_reason": primary_reason,
            "report_path": report_path,
            "rules_zip_path": rules_zip_path,
            "content_hash": content_hash,
            "report_sha256": report_sha256,
            "rules_sha256": rules_sha256,
            "retention_until": retention_until.isoformat(),
            "kev_listed": bool(kev_listed),
            "signed_url_expiry_seconds": signed_url_expiry_seconds,
        }
        self.sb.table("report_objects").insert(row).execute()

    def list_expired_report_objects(self) -> list[dict[str, Any]]:
        """
        view: public.v_expired_report_objects
        """
        res = self.sb.table("v_expired_report_objects").select("*").limit(1000).execute()
        return res.data or []

    def delete_report_object_rows(self, report_ids: list[str]) -> None:
        if not report_ids:
            return
        # delete by report_id in (...)
        self.sb.table("report_objects").delete().in_("report_id", report_ids).execute()

    # -------------------------
    # Housekeeping DB function call
    # -------------------------
    def run_housekeeping_db(self) -> None:
        """
        public.argus_housekeeping_db() 호출
        """
        self.sb.rpc("argus_housekeeping_db", {}).execute()
