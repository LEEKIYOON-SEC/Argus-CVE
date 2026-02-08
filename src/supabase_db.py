from __future__ import annotations

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

log = logging.getLogger("argus.supabase_db")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class SupabaseDB:
    """
    Supabase PostgREST wrapper (service_role key 권장)
    - argus schema(비-public) 접근을 위해 Accept-Profile/Content-Profile 기본 적용
    """

    def __init__(self, supabase_url: str, supabase_key: str, schema: str = "argus"):
        self.url = (supabase_url or "").rstrip("/")
        self.key = supabase_key or ""
        self.schema = os.getenv("SUPABASE_SCHEMA", schema) or schema

        if not self.url:
            raise ValueError("SUPABASE_URL missing")
        if not self.key:
            raise ValueError("SUPABASE_KEY missing")

    # ----------------------------
    # low-level REST helpers
    # ----------------------------
    def _headers(self, *, profile: bool = True) -> Dict[str, str]:
        h = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Accept": "application/json",
            "User-Agent": "Argus-AI-Threat-Intelligence/1.0",
        }
        if profile and self.schema:
            # PostgREST: non-public schema 접근 시 필요할 수 있음
            h["Accept-Profile"] = self.schema
            h["Content-Profile"] = self.schema
        return h

    def _rest_url(self, table: str) -> str:
        return f"{self.url}/rest/v1/{table}"

    def _get(self, table: str, *, params: Dict[str, str], timeout: int = 20) -> List[Dict[str, Any]]:
        r = requests.get(self._rest_url(table), headers=self._headers(profile=True), params=params, timeout=timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {table} failed {r.status_code}: {r.text[:400]}")
        j = r.json()
        return j if isinstance(j, list) else []

    def _post(self, table: str, *, payload: Any, params: Optional[Dict[str, str]] = None, timeout: int = 25) -> None:
        h = self._headers(profile=True)
        h["Content-Type"] = "application/json"
        r = requests.post(self._rest_url(table), headers=h, params=params or {}, json=payload, timeout=timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"POST {table} failed {r.status_code}: {r.text[:400]}")

    def _patch(self, table: str, *, payload: Any, params: Dict[str, str], timeout: int = 25) -> None:
        h = self._headers(profile=True)
        h["Content-Type"] = "application/json"
        r = requests.patch(self._rest_url(table), headers=h, params=params, json=payload, timeout=timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"PATCH {table} failed {r.status_code}: {r.text[:400]}")

    def _delete(self, table: str, *, params: Dict[str, str], timeout: int = 25) -> None:
        r = requests.delete(self._rest_url(table), headers=self._headers(profile=True), params=params, timeout=timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"DELETE {table} failed {r.status_code}: {r.text[:400]}")

    # ----------------------------
    # runs log (best-effort)
    # ----------------------------
    def log_run(self, run_type: str, ok: bool, message: str) -> None:
        # 테이블이 없을 수도 있으니 best-effort
        try:
            self._post(
                "runs",
                payload={
                    "run_type": run_type,
                    "ok": bool(ok),
                    "message": message,
                    "created_at": _iso(_utcnow()),
                },
            )
        except Exception:
            # 운영상 log table이 없어도 파이프라인은 계속 돌아야 함
            pass

    # ----------------------------
    # settings (argus.settings)
    # ----------------------------
    def get_setting_text(self, key: str) -> Optional[str]:
        rows = self._get("settings", params={"select": "value", "key": f"eq.{key}"})
        if not rows:
            return None
        v = (rows[0].get("value") or "").strip()
        return v if v else None

    def set_setting_text(self, key: str, value: str, description: Optional[str] = None) -> None:
        # upsert: Prefer resolution=merge-duplicates header 방식도 있으나,
        # PostgREST/Supabase 설정 편차가 있어 "있으면 patch, 없으면 insert"로 구현
        existing = self._get("settings", params={"select": "key", "key": f"eq.{key}"})
        if existing:
            payload: Dict[str, Any] = {"value": str(value), "updated_at": _iso(_utcnow())}
            if description is not None:
                payload["description"] = description
            self._patch("settings", payload=payload, params={"key": f"eq.{key}"})
        else:
            payload = {
                "key": key,
                "value": str(value),
                "description": description,
                "updated_at": _iso(_utcnow()),
            }
            self._post("settings", payload=payload)

    # ----------------------------
    # CVE state (best-effort)
    # ----------------------------
    def get_last_poll_time(self, default_minutes: int = 60) -> datetime:
        """
        가장 최근 run 시간 기반으로 since를 계산(없으면 now - default)
        테이블/컬럼이 없으면 안전하게 fallback.
        """
        now = _utcnow()
        try:
            rows = self._get("runs", params={"select": "created_at", "order": "created_at.desc", "limit": "1"})
            if not rows:
                return now - timedelta(minutes=default_minutes)
            ts = rows[0].get("created_at")
            if not ts:
                return now - timedelta(minutes=default_minutes)
            # ISO parse best-effort
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                return now - timedelta(minutes=default_minutes)
        except Exception:
            return now - timedelta(minutes=default_minutes)

    def get_cve_state(self, cve_id: str) -> Optional[Dict[str, Any]]:
        try:
            rows = self._get("cve_state", params={"select": "*", "cve_id": f"eq.{cve_id}", "limit": "1"})
            return rows[0] if rows else None
        except Exception:
            return None

    def upsert_cve_state(self, cve: Dict[str, Any], **extra) -> None:
        """
        프로젝트에서 사용하는 cve_state 테이블이 이미 존재한다는 전제(best-effort).
        존재하지 않으면 예외를 삼키고 파이프라인을 계속.
        """
        try:
            cve_id = cve.get("cve_id")
            if not cve_id:
                return

            existing = self.get_cve_state(cve_id)
            payload: Dict[str, Any] = {"last_seen_at": _iso(_utcnow())}
            payload.update(extra or {})

            # 최소한의 필드들만 저장(테이블 스키마 차이에 대한 내성)
            for k in [
                "cve_id",
                "summary",
                "cvss_score",
                "cvss_vector",
                "attack_vector",
                "epss_score",
                "is_cisa_kev",
            ]:
                if k in cve and cve[k] is not None:
                    payload[k] = cve[k]

            if existing:
                self._patch("cve_state", payload=payload, params={"cve_id": f"eq.{cve_id}"})
            else:
                payload["cve_id"] = cve_id
                self._post("cve_state", payload=payload)
        except Exception:
            pass

    # ----------------------------
    # report artifacts (argus.report_artifacts)
    # ----------------------------
    def insert_report_artifact(
        self,
        *,
        cve_id: str,
        alert_type: str,
        notify_reason: str,
        object_path: str,
        kind: str,
        sha256: str,
        bytes_len: int,
    ) -> None:
        self._post(
            "report_artifacts",
            payload={
                "cve_id": cve_id,
                "alert_type": alert_type,
                "notify_reason": notify_reason,
                "object_path": object_path,
                "kind": kind,
                "sha256": sha256,
                "bytes": int(bytes_len),
                "created_at": _iso(_utcnow()),
            },
        )

    def list_report_artifacts_older_than(self, cutoff: datetime, limit: int = 200) -> List[Dict[str, Any]]:
        # created_at < cutoff
        return self._get(
            "report_artifacts",
            params={
                "select": "id,object_path,kind,created_at",
                "created_at": f"lt.{_iso(cutoff)}",
                "order": "created_at.asc",
                "limit": str(limit),
            },
            timeout=30,
        )

    def delete_report_artifact_row(self, artifact_id: int) -> None:
        self._delete("report_artifacts", params={"id": f"eq.{artifact_id}"})

    # ----------------------------
    # optional cleanup helpers (best-effort)
    # ----------------------------
    def delete_cve_state_older_than(self, cutoff: datetime, *, only_low: bool = False) -> None:
        """
        cve_state 정리(테이블이 없거나 컬럼이 없으면 실패해도 무시되는 best-effort로 쓰는 걸 권장)
        """
        try:
            params = {"last_seen_at": f"lt.{_iso(cutoff)}"}
            if only_low:
                # 스키마가 다를 수 있으므로 best-effort: cvss_score <= 3.9 같은 룰을 쓰려면
                # PostgREST 표현식이 필요. 여기서는 안전하게 last_seen_at만 기준으로 삭제.
                pass
            self._delete("cve_state", params=params)
        except Exception:
            pass

    def delete_cve_state_older_than_days(self, days: int) -> int:
        """
        cve_state에서 last_seen_at이 (now - days)보다 오래된 row 삭제.
        반환: 시도한 삭제 건수(정확하지 않을 수 있음, best-effort)
        """
        try:
            days = int(days)
            cutoff = _utcnow() - timedelta(days=days)
            # PostgREST: DELETE with filter
            self._delete("cve_state", params={"last_seen_at": f"lt.{_iso(cutoff)}"})
            return 1
        except Exception:
            return 0

    def delete_cve_state_low_older_than_days(self, days: int, low_cvss_max: float = 3.9) -> int:
        """
        cve_state에서:
          - last_seen_at < now-days
          - AND cvss_score <= low_cvss_max
        삭제 (테이블/컬럼 편차가 있을 수 있어 best-effort)
        """
        try:
            days = int(days)
            cutoff = _utcnow() - timedelta(days=days)
            # PostgREST filter: multiple params are AND
            self._delete(
                "cve_state",
                params={
                    "last_seen_at": f"lt.{_iso(cutoff)}",
                    "cvss_score": f"lte.{float(low_cvss_max)}",
                },
            )
            return 1
        except Exception:
            # cvss_score 컬럼이 없다면 실패할 수 있음 -> 무시
            return 0
