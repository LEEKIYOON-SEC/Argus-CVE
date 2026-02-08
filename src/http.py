from __future__ import annotations

import time
import random
from typing import Optional, Dict, Any, Set

import requests


class HttpError(RuntimeError):
    """Backwards-compatible error type for existing modules."""
    pass


# Alias for modules that import HTTPError
HTTPError = HttpError


def _sleep_backoff(attempt: int, base: float = 1.0, cap: float = 20.0) -> None:
    """
    Exponential backoff with jitter.
    attempt: 0..N
    """
    t = min(cap, base * (2 ** attempt))
    t = t * (0.7 + random.random() * 0.6)
    time.sleep(t)


def _default_retry_statuses() -> Set[int]:
    return {429, 500, 502, 503, 504}


def _sleep_retry_after(headers: Dict[str, str], attempt: int) -> None:
    ra = headers.get("Retry-After")
    if ra:
        try:
            time.sleep(min(60, int(ra)))
            return
        except Exception:
            pass
    _sleep_backoff(attempt)


def http_get_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: int = 25,
    max_retries: int = 4,
    retry_on_status: Optional[Set[int]] = None,
) -> Any:
    """
    Compatibility wrapper expected by existing modules:
      from .http import http_get_json, HttpError

    - Retries on {429, 500, 502, 503, 504} by default
    - Retries on network errors
    - Returns parsed JSON
    """
    retry_on_status = retry_on_status or _default_retry_statuses()

    last_err: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout)

            if r.status_code in retry_on_status:
                last_err = HttpError(f"GET {url} retryable status={r.status_code} body={r.text[:300]}")
                if attempt < max_retries:
                    _sleep_retry_after(r.headers, attempt)
                    continue

            if r.status_code >= 400:
                raise HttpError(f"GET {url} failed status={r.status_code} body={r.text[:500]}")

            try:
                return r.json()
            except Exception as e:
                raise HttpError(f"GET {url} json parse failed: {e} body={r.text[:300]}")

        except (requests.RequestException, HttpError) as e:
            last_err = e
            if attempt < max_retries:
                _sleep_backoff(attempt)
                continue
            break

    raise HttpError(str(last_err))


def http_get(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: int = 40,
    max_retries: int = 4,
    retry_on_status: Optional[Set[int]] = None,
    return_bytes: bool = True,
) -> Any:
    """
    Compatibility helper expected by rules_official/patch modules.
    - Downloads non-JSON content (zip/tar/gz/html/txt/pdf)
    - By default returns bytes (return_bytes=True)
    - If return_bytes=False returns text decoded as utf-8 (errors='ignore')
    """
    retry_on_status = retry_on_status or _default_retry_statuses()

    last_err: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout, allow_redirects=True)

            if r.status_code in retry_on_status:
                last_err = HttpError(f"GET {url} retryable status={r.status_code} body={r.text[:200]}")
                if attempt < max_retries:
                    _sleep_retry_after(r.headers, attempt)
                    continue

            if r.status_code >= 400:
                raise HttpError(f"GET {url} failed status={r.status_code} body={r.text[:400]}")

            if return_bytes:
                return r.content
            return r.content.decode("utf-8", errors="ignore")

        except (requests.RequestException, HttpError) as e:
            last_err = e
            if attempt < max_retries:
                _sleep_backoff(attempt)
                continue
            break

    raise HttpError(str(last_err))


def http_head(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: int = 25,
    max_retries: int = 3,
    retry_on_status: Optional[Set[int]] = None,
) -> Dict[str, str]:
    """
    Compatibility helper expected by patch_intel and others.
    - Performs HTTP HEAD and returns response headers
    - Retries on {429, 500, 502, 503, 504} by default
    - allow_redirects=True to follow common redirect chains for PDFs/patch docs
    """
    retry_on_status = retry_on_status or _default_retry_statuses()

    last_err: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            r = requests.head(url, headers=headers, params=params, timeout=timeout, allow_redirects=True)

            if r.status_code in retry_on_status:
                last_err = HttpError(f"HEAD {url} retryable status={r.status_code}")
                if attempt < max_retries:
                    _sleep_retry_after(r.headers, attempt)
                    continue

            if r.status_code >= 400:
                raise HttpError(f"HEAD {url} failed status={r.status_code}")

            return dict(r.headers)

        except (requests.RequestException, HttpError) as e:
            last_err = e
            if attempt < max_retries:
                _sleep_backoff(attempt)
                continue
            break

    raise HttpError(str(last_err))


def request_json(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    json: Optional[Any] = None,
    data: Optional[bytes] = None,
    timeout: int = 25,
    max_retries: int = 4,
    retry_on_status: Optional[Set[int]] = None,
) -> Any:
    """
    Generic JSON request helper (newer modules).
    """
    retry_on_status = retry_on_status or _default_retry_statuses()

    last_err: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            r = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json,
                data=data,
                timeout=timeout,
                allow_redirects=True,
            )

            if r.status_code in retry_on_status:
                last_err = HttpError(f"{method} {url} retryable status={r.status_code} body={r.text[:300]}")
                if attempt < max_retries:
                    _sleep_retry_after(r.headers, attempt)
                    continue

            if r.status_code >= 400:
                raise HttpError(f"{method} {url} failed status={r.status_code} body={r.text[:500]}")

            try:
                return r.json()
            except Exception as e:
                raise HttpError(f"{method} {url} json parse failed: {e} body={r.text[:300]}")

        except (requests.RequestException, HttpError) as e:
            last_err = e
            if attempt < max_retries:
                _sleep_backoff(attempt)
                continue
            break

    raise HttpError(str(last_err))
