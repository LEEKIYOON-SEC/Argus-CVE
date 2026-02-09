import requests
import os

class SlackNotifier:
    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    def send_alert(self, cve_data, reason, report_url=None):
        clean_reason = reason.split(' (')[0] if ' (' in reason else reason
        emoji = "🚨" if "KEV" in reason else "🆕"
        
        display_title = cve_data.get('title_ko', cve_data.get('title', 'N/A'))
        display_desc = cve_data.get('desc_ko', cve_data.get('summary_ko', cve_data['description']))
        cwe_info = ", ".join(cve_data.get('cwe', [])) if cve_data.get('cwe') else "N/A"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {clean_reason}: {cve_data['id']}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title:*\n{display_title}"}
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CVSS:*\n{cve_data['cvss']}"},
                    {"type": "mrkdwn", "text": f"*EPSS:*\n{cve_data['epss']*100:.2f}%"},
                    {"type": "mrkdwn", "text": f"*CWE:*\n{cwe_info}"}, # CWE 추가
                ]
            }
        ]

        if "(" in reason and "*" not in reason:
            target_info = reason.split('(')[-1].replace(')', '')
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"🎯 *Target Asset:* {target_info}"}]
            })
        
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{display_desc}"}
        })

        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📄 상세 분석 리포트 확인 (30일 유효)"},
                        "url": report_url,
                        "style": "primary"
                    }
                ]
            })

        requests.post(self.webhook_url, json={"blocks": blocks})