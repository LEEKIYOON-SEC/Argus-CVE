from __future__ import annotations

import json
import logging
from typing import Any

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

log = logging.getLogger("argus.slack")


@retry(
    reraise=True,
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((requests.Timeout, requests.ConnectionError)),
)
def post_slack(webhook_url: str, text: str, extra: dict[str, Any] | None = None) -> None:
    """
    Slack Incoming Webhook 전송.
    - 길이가 길어지는 케이스: 상위 레벨에서 Report 링크 중심으로 구성(설계 반영)
    - 여기서는 안정적으로 전송/재시도만 담당
    """
    payload: dict[str, Any] = {"text": text}
    if extra:
        payload.update(extra)

    resp = requests.post(
        webhook_url,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=20,
    )

    if resp.status_code >= 400:
        raise RuntimeError(f"Slack webhook failed: HTTP {resp.status_code} :: {resp.text[:300]}")

    log.info("Slack notified (%d chars)", len(text))
