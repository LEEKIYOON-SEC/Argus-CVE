from __future__ import annotations

import time
import logging
from typing import Optional, Dict, Any, List

from .http import request_json, HttpError

log = logging.getLogger("argus.settings_store")

# settings cache (avoid hitting Supabase too frequently)
_CACHE: Dict[str, Any] = {
    "ts": 0.0,
    "settings": {},          # key -> value(str)
    "trusted_repos": None,   # list[dict]
}


def _cache_ttl_sec() -> int:
    import os
    try:
        return int(os.getenv("ARGUS_SETTINGS_CACHE_TTL_SEC", "300").strip())
    except Exception:
        return 300


def _supabase_headers(cfg) -> Dict[str, str]:
    # IMPORTANT: use argus schema via PostgREST profiles
    return {
        "apikey": cfg.SUPABASE_KEY,
        "Authorization": f"Bearer {cfg.SUPABASE_KEY}",
        "Accept": "application/json",
        "Accept-Profile": "argus",
        "Content-Profile": "argus",
    }


def _rest_url(cfg, table: str) -> str:
    base = cfg.SUPABASE_URL.rstrip("/")
    return f"{base}/rest/v1/{table}"


def _refresh_settings(cfg) -> None:
    url = _rest_url(cfg, "settings")
    headers = _supabase_headers(cfg)

    # select key,value only
    try:
        rows = request_json(
            "GET",
            url,
            headers=headers,
            params={"select": "key,value"},
            timeout=20,
            max_retries=2,
        )
        if isinstance(rows, list):
            m = {}
            for r in rows:
                k = (r.get("key") or "").strip()
                v = r.get("value")
                if k:
                    m[k] = "" if v is None else str(v)
            _CACHE["settings"] = m
            _CACHE["ts"] = time.time()
            return
    except Exception as e:
        log.info("settings fetch failed: %s", e)


def _refresh_trusted_repos(cfg) -> None:
    url = _rest_url(cfg, "trusted_github_repos")
    headers = _supabase_headers(cfg)

    try:
        rows = request_json(
            "GET",
            url,
            headers=headers,
            params={"select": "owner,repo,trust_level,enabled"},
            timeout=20,
            max_retries=2,
        )
        if isinstance(rows, list):
            out = []
            for r in rows:
                if r.get("enabled") is False:
                    continue
                out.append(r)
            _CACHE["trusted_repos"] = out
            _CACHE["ts"] = time.time()
            return
    except Exception as e:
        log.info("trusted repos fetch failed: %s", e)


def _ensure_cache(cfg) -> None:
    ttl = _cache_ttl_sec()
    if (time.time() - float(_CACHE.get("ts") or 0.0)) < ttl and _CACHE.get("settings"):
        return
    _refresh_settings(cfg)
    # trusted repos도 같이 갱신(없어도 동작은 하게 best-effort)
    _refresh_trusted_repos(cfg)


def get_setting_text(cfg, key: str) -> Optional[str]:
    _ensure_cache(cfg)
    v = (_CACHE.get("settings") or {}).get(key)
    return v if v is not None else None


def get_setting_int(cfg, key: str, default: int) -> int:
    v = get_setting_text(cfg, key)
    if v is None:
        return default
    try:
        return int(v.strip())
    except Exception:
        return default


def get_setting_float(cfg, key: str, default: float) -> float:
    v = get_setting_text(cfg, key)
    if v is None:
        return default
    try:
        return float(v.strip())
    except Exception:
        return default


def get_trusted_github_repos(cfg) -> List[dict]:
    _ensure_cache(cfg)
    return list(_CACHE.get("trusted_repos") or [])
