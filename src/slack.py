from __future__ import annotations

import os

from .http import request_json, HTTPError


def post_slack(webhook_url: str, text: str) -> None:
    if not webhook_url:
        raise RuntimeError("SLACK_WEBHOOK_URL missing")

    payload = {"text": text}

    try:
        # Slack incoming webhook: JSON POST, response is "ok" text (not JSON) sometimes.
        # request_json은 json 파싱을 전제로 해서, 여기서는 requests를 직접 쓰지 않고,
        # Slack에 대해서만 예외 처리: json parse 실패를 허용하는 형태로 바꿔도 되지만
        # 단순성을 위해 Slack은 최소 재시도만 수행하는 별도 로직을 둡니다.
        import requests

        timeout = int(os.getenv("SLACK_TIMEOUT", "20"))
        max_retries = int(os.getenv("SLACK_MAX_RETRIES", "3"))

        last = None
        for i in range(max_retries + 1):
            try:
                r = requests.post(webhook_url, json=payload, timeout=timeout)
                if r.status_code >= 400:
                    last = RuntimeError(f"slack webhook failed {r.status_code}: {r.text[:200]}")
                    continue
                return
            except requests.RequestException as e:
                last = e
                continue

        if last:
            raise last

    except Exception as e:
        # Slack 실패가 전체 파이프라인을 깨면 운영성이 나빠짐.
        # 단, 초기에 디버깅을 위해 실패를 raise 하고 싶다면 env로 제어 가능.
        if os.getenv("ARGUS_FAIL_ON_SLACK", "false").strip().lower() in ("1", "true", "yes", "y", "on"):
            raise
        # best-effort: 그냥 무시
        return
