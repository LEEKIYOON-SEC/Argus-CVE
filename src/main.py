import os
import datetime
import time
import json
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
    """슬랙용 요약 (JSON 요청으로 안정성 강화)"""
    prompt = f"""
    Task: Translate Title and Summarize Description into Korean.
    [Input] Title: {cve_data['title']} / Desc: {cve_data['description']}
    [Output] JSON Only: {{"title": "Korean Title", "summary": "Korean Summary (Max 3 lines)"}}
    """
    try:
        response = client.models.generate_content(
            model=config.MODEL_PHASE_0, contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json", # JSON 강제
                safety_settings=[types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE")]
            )
        )
        data = json.loads(response.text)
        return data.get("title", cve_data['title']), data.get("summary", cve_data['description'][:200])
    except:
        return cve_data['title'], cve_data['description'][:200]

def generate_report_content(cve_data, reason):
    """HTML 리포트 생성 (Python이 조립)"""
    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    ref_list = "".join([f"<li><a href='{r}' target='_blank'>{r[:80]}...</a></li>" for r in cve_data['references']])
    
    score = cve_data['cvss']
    badge_color = "bg-gray"
    if score >= 9.0: badge_color = "bg-red"
    elif score >= 7.0: badge_color = "bg-orange"
    elif score >= 4.0: badge_color = "bg-green"

    # Affected Table Rows
    affected_html = ""
    for item in cve_data.get('affected', []):
        affected_html += f"<tr><th>Vendor</th><td>{item['vendor']}</td></tr><tr><th>Product</th><td>{item['product']}</td></tr><tr><th>Affected</th><td>{item['versions']}</td></tr>"

    # AI에게 분석 내용을 JSON으로 요청 (HTML 태그 생성 X)
    prompt = f"""
    Role: Security Analyst.
    Task: Analyze CVE and provide structured output in Korean.
    [Data] Title: {cve_data['title']} / Desc: {cve_data['description']}
    [Output] JSON Only:
    {{
        "summary": "Detailed summary in Korean",
        "attack_vector": "How the attack works",
        "impact": "Potential impact",
        "mitigation": ["Step 1", "Step 2", "Step 3"]
    }}
    """
    
    ai_summary = "분석 실패"
    ai_vector = "정보 없음"
    ai_impact = "정보 없음"
    mitigation_list = "<li>정보 없음</li>"
    
    try:
        response = client.models.generate_content(
            model=config.MODEL_PHASE_0, contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json", # JSON 모드
                safety_settings=[types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE")]
            )
        )
        data = json.loads(response.text)
        ai_summary = data.get("summary", "분석 실패")
        ai_vector = data.get("attack_vector", "정보 없음")
        ai_impact = data.get("impact", "정보 없음")
        
        # 대응 방안 리스트 HTML 변환
        mitigation_list = "".join([f"<li>{step}</li>" for step in data.get("mitigation", [])])
    except Exception as e:
        print(f"[WARN] AI Analysis Failed: {e}")

    # Python에서 HTML 조립 (오류 없음)
    return f"""
    <div class="header">
        <span class="meta-tag">Detected: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
        <span class="meta-tag">Reason: {reason}</span>
        <h1>🛡️ {cve_data['title_ko']}</h1>
        <div style="margin-top:10px;">
            <span class="badge {badge_color}">CVSS {score}</span>
            <span class="badge bg-gray">EPSS {cve_data['epss']*100:.2f}%</span>
            <span class="badge {'bg-red' if cve_data['is_kev'] else 'bg-gray'}">KEV {'YES' if cve_data['is_kev'] else 'No'}</span>
            <span class="badge bg-gray">{cwe_str}</span>
        </div>
    </div>

    <div class="card">
        <div class="card-title">📦 Affected Assets</div>
        <table class="ai-table">
            {affected_html if affected_html else "<tr><td>정보 없음</td></tr>"}
        </table>
    </div>

    <div class="card">
        <div class="card-title">🔍 Vulnerability Analysis</div>
        <table class="ai-table">
            <tr><th>요약</th><td>{ai_summary}</td></tr>
            <tr><th>공격 벡터</th><td>{ai_vector}</td></tr>
            <tr><th>영향도</th><td>{ai_impact}</td></tr>
        </table>
    </div>

    <div class="card">
        <div class="card-title">🛡️ Mitigation Strategies</div>
        <div class="mitigation-box">
            <ul>{mitigation_list}</ul>
        </div>
    </div>

    <div class="card">
        <div class="card-title">🔗 References</div>
        <ul style="font-size:13px; color:#64748b;">
            {ref_list if ref_list else "<li>No references provided.</li>"}
        </ul>
    </div>
    """

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
                "affected": raw_data['affected']
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
                
                # JSON 방식으로 제목/요약 생성
                title_ko, desc_ko = generate_korean_summary(current_state)
                current_state['title_ko'] = title_ko
                current_state['desc_ko'] = desc_ko
                
                report_content = generate_report_content(current_state, alert_reason)
                report_url = db.upload_report(cve_id, report_content)
                notifier.send_alert(current_state, alert_reason, report_url['signedURL'])
                
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