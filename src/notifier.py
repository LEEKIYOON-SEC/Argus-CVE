import requests
import os

class SlackNotifier:
    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    def send_alert(self, cve_data, reason, report_url=None):
        """Slack Block Kit 메시지 전송"""
        
        emoji = "⚠️"
        if "KEV" in reason: emoji = "🚨"
        elif "NEW" in reason: emoji = "🆕"
        elif "Surge" in reason: emoji = "📈"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {reason}: {cve_data['id']}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CVSS Score:*\n{cve_data['cvss']}"},
                    {"type": "mrkdwn", "text": f"*EPSS Probability:*\n{cve_data['epss']} ({cve_data['epss']*100:.2f}%)"},
                    {"type": "mrkdwn", "text": f"*KEV Listed:*\n{'✅ YES' if cve_data['is_kev'] else '❌ No'}"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Target Matched:*\n{reason.split('(')[-1].replace(')', '') if '(' in reason else 'Unknown'}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{cve_data['description'][:200]}..."
                }
            }
        ]

        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "📄 상세 한글 리포트 보기"
                        },
                        "url": report_url,
                        "style": "primary"
                    }
                ]
            })

        payload = {"blocks": blocks}
        try:
            requests.post(self.webhook_url, json=payload)
        except Exception as e:
            print(f"[ERR] Slack send failed: {e}")