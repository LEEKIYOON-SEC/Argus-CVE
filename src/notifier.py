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

        # [추가] Vendor/Product 정보 포맷팅
        affected_info = "N/A"
        if cve_data.get('affected'):
            # 첫 번째 영향받는 자산만 표시 (너무 길어지는 것 방지)
            first = cve_data['affected'][0]
            affected_info = f"*Vendor:* {first['vendor']}\n*Product:* {first['product']}\n*Versions:* {first['versions']}"
            if len(cve_data['affected']) > 1:
                affected_info += f"\n(외 {len(cve_data['affected'])-1}건)"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {clean_reason}: {cve_data['id']}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title:*\n{display_title}"},
                    {"type": "mrkdwn", "text": f"{affected_info}"} # Vendor 정보 추가
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CVSS:*\n{cve_data['cvss']}"},
                    {"type": "mrkdwn", "text": f"*EPSS:*\n{cve_data['epss']*100:.2f}%"},
                    {"type": "mrkdwn", "text": f"*KEV:*\n{'✅ YES' if cve_data['is_kev'] else '❌ No'}"},
                    {"type": "mrkdwn", "text": f"*CWE:*\n{cwe_info}"},
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