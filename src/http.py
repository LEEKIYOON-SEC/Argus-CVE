from __future__ import annotations

import time
import random
from typing import Optional, Dict, Any

import requests


class HTTPError(RuntimeError):
    pass


def _sleep_backoff(attempt: int, base: float = 1.0, cap: float = 20.0) -> None:
    # exponential backoff + jitter
    t = min(cap, base * (2 ** attempt))
    t = t * (0.7 + random.random() * 0.6)
    time.sleep(t)


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
    retry_on_status: Optional[set[int]] = None,
) -> Any:
    """
    표준 HTTP 호출:
    - 기본 retry 대상: 429, 500, 502, 503, 504
    - 네트워크 예외도 retry
    - 성공 시 json 반환, 실패 시 HTTPError
    """
    if retry_on_status is None:
        retry_on_status = {429, 500, 502, 503, 504}

    last_err = None
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
            )

            if r.status_code in retry_on_status:
                last_err = HTTPError(f"{method} {url} retryable status={r.status_code} body={r.text[:300]}")
                if attempt < max_retries:
                    # Retry-After가 있으면 반영
                    ra = r.headers.get("Retry-After")
                    if ra:
                        try:
                            time.sleep(min(60, int(ra)))
                        except Exception:
                            _sleep_backoff(attempt)
                    else:
                        _sleep_backoff(attempt)
                    continue

            if r.status_code >= 400:
                raise HTTPError(f"{method} {url} failed status={r.status_code} body={r.text[:500]}")

            # json 응답 가정
            return r.json()

        except (requests.RequestException, ValueError, HTTPError) as e:
            last_err = e
            if attempt < max_retries:
                _sleep_backoff(attempt)
                continue
            break

    raise HTTPError(str(last_err))
