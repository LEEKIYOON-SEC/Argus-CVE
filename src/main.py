import os
import datetime
import time
import json
import requests
from google import genai
from google.genai import types
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
import config

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

def is_target_asset(cve_description, cve_id):
    desc_lower = cve_description.lower()
    for target in config.TARGET_ASSETS:
        vendor, product = target.get('vendor', '').lower(), target.get('product', '').lower()
        if vendor == "*" and product == "*": return True, "All Assets (*)"
        if vendor in desc_lower and (product == "*" or product in desc_lower):
            return True, f"Matched: {vendor}/{product}"
    return False, None

def generate_korean_summary(cve_data):
    """슬랙용 한글 요약 (텍스트 파싱)"""
    prompt = f"""
    Task: Translate Title and Summarize Description into Korean.
    [Input] Title: {cve_data['title']} / Desc: {cve_data['description']}
    [Format]
    제목: [Korean Title]
    내용: [Korean Summary (Max 3 lines)]
    Do NOT add intro/outro.
    """
    try:
        response = client.models.generate_content(
            model=config.MODEL_PHASE_0, contents=prompt,
            config=types.GenerateContentConfig(safety_settings=[types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE")])
        )
        text = response.text.strip()
        title_ko, desc_ko = cve_data['title'], cve_data['description'][:200]
        for line in text.split('\n'):
            if line.startswith("제목:"): title_ko = line.replace("제목:", "").strip()
            if line.startswith("내용:"): desc_ko = line.replace("내용:", "").strip()
        return title_ko, desc_ko
    except: return cve_data['title'], cve_data['description'][:200]

def create_github_issue(cve_data, reason):
    """
    [New] GitHub Issue를 생성하고 해당 URL 반환 (무조건 렌더링 성공)
    """
    token = os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY") # 예: user/repo
    if not repo: return None

    # 1. AI 분석 (JSON)
    prompt = f"""
    Analyze this CVE in Korean.
    Title: {cve_data['title']}
    Desc: {cve_data['description']}
    
    Output JSON:
    {{
        "summary": "Detailed summary",
        "vector": "Attack vector",
        "impact": "Impact",
        "mitigation": ["Step 1", "Step 2"]
    }}
    """
    ai_summary, ai_vector, ai_impact, ai_mitigation = "분석 대기", "-", "-", ["정보 없음"]
    try:
        response = client.models.generate_content(
            model=config.MODEL_PHASE_0, contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                safety_settings=[types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE")]
            )
        )
        data = json.loads(response.text)
        ai_summary = data.get("summary", "-")
        ai_vector = data.get("vector", "-")
        ai_impact = data.get("impact", "-")
        ai_mitigation = data.get("mitigation", [])
    except: pass

    # 2. Markdown 본문 작성 (GitHub 스타일)
    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    cce_str = ", ".join(cve_data['cce']) if cve_data['cce'] else "N/A"
    
    # 뱃지 (Shields.io)
    score = cve_data['cvss']
    color = "lightgrey"
    if score >= 9.0: color = "critical"
    elif score >= 7.0: color = "orange"
    elif score >= 4.0: color = "yellow"
    elif score > 0: color = "green"
    
    badges = f"![CVSS](https://img.shields.io/badge/CVSS-{score}-{color}) ![EPSS](https://img.shields.io/badge/EPSS-{cve_data['epss']*100:.2f}%25-blue) ![KEV](https://img.shields.io/badge/KEV-{'YES' if cve_data['is_kev'] else 'No'}-{'red' if cve_data['is_kev'] else 'lightgrey'})"

    affected_rows = "| Vendor | Product | Versions |\n|---|---|---|\n"
    for item in cve_data.get('affected', []):
        affected_rows += f"| {item['vendor']} | {item['product']} | {item['versions']} |\n"

    mitigation_list = "\n".join([f"- {m}" for m in ai_mitigation])
    ref_list = "\n".join([f"- {r}" for r in cve_data['references']])

    body = f"""
# 🛡️ {cve_data['title_ko']}

> **Detected:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}  
> **Reason:** {reason}

{badges}
**CWE:** {cwe_str} | **CCE:** {cce_str}

## 📦 영향 받는 자산 (Affected Assets)
{affected_rows}

## 🔍 취약점 분석 (Analysis)
| 항목 | 내용 |
| :--- | :--- |
| **요약** | {ai_summary} |
| **공격 벡터** | {ai_vector} |
| **영향도** | {ai_impact} |

## 🛡️ 대응 방안 (Mitigation)
{mitigation_list}

## 🔗 참고 자료 (References)
{ref_list}
    """

    # 3. GitHub API로 Issue 생성
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    payload = {"title": f"[Argus] {cve_data['id']}: {cve_data['title_ko']}", "body": body, "labels": ["security", "cve"]}
    
    resp = requests.post(url, headers=headers, json=payload)
    if resp.status_code == 201:
        return resp.json().get("html_url") # 생성된 이슈 URL 반환
    else:
        print(f"[ERR] Issue Creation Failed: {resp.text}")
        return None

def main():
    print(f"[*] Argus Phase 0 시작 (모델: {config.MODEL_PHASE_0})")
    collector, db, notifier = Collector(), ArgusDB(), SlackNotifier()
    collector.fetch_kev()
    target_cve_ids = collector.fetch_recent_cves(hours=2)
    if not target_cve_ids: return
    collector.fetch_epss(target_cve_ids)
    print(f"[*] 분석 대상: {len(target_cve_ids)}건")

    for cve_id in target_cve_ids:
        try:
            time.sleep(20)
            raw_data = collector.enrich_cve(cve_id)
            if raw_data.get('state') != 'PUBLISHED': continue
            is_target, match_info = is_target_asset(raw_data['description'], cve_id)
            if not is_target: continue

            current_state = {
                "id": cve_id, "title": raw_data['title'], "cvss": raw_data['cvss'],
                "is_kev": cve_id in collector.kev_set, "epss": collector.epss_cache.get(cve_id, 0.0),
                "description": raw_data['description'],
                "cwe": raw_data['cwe'], "references": raw_data['references'],
                "affected": raw_data['affected'], "cce": raw_data['cce']
            }
            
            last_record = db.get_cve(cve_id)
            last_state = last_record['last_alert_state'] if last_record else None
            should_alert, alert_reason = False, ""
            
            if last_record is None: should_alert, alert_reason = True, f"신규 취약점 ({match_info})"
            else:
                if current_state['is_kev'] and not last_state.get('is_kev'): should_alert, alert_reason = True, "🚨 KEV 등재"
                elif current_state['epss'] >= 0.1 and (current_state['epss'] - last_state.get('epss', 0)) > 0.05: should_alert, alert_reason = True, "📈 EPSS 급증"

            if should_alert:
                print(f"[!] 알림 발송: {cve_id}")
                title_ko, desc_ko = generate_korean_summary(current_state)
                current_state['title_ko'] = title_ko
                current_state['desc_ko'] = desc_ko
                
                # [변경] GitHub Issue 생성
                report_url = create_github_issue(current_state, alert_reason)
                
                notifier.send_alert(current_state, alert_reason, report_url)
                
                db.upsert_cve({
                    "id": cve_id, "cvss_score": current_state['cvss'], "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'], "last_alert_at": datetime.datetime.now().isoformat(),
                    "last_alert_state": current_state, "updated_at": datetime.datetime.now().isoformat()
                })
            else:
                db.upsert_cve({"id": cve_id, "updated_at": datetime.datetime.now().isoformat()})
        except Exception as e:
            print(f"[ERR] {cve_id}: {e}")

if __name__ == "__main__":
    main()