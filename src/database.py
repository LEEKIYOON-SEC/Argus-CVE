import os
from supabase import create_client, Client

class ArgusDB:
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        self.client: Client = create_client(url, key)

    def get_cve(self, cve_id):
        response = self.client.table("cves").select("*").eq("id", cve_id).execute()
        return response.data[0] if response.data else None

    def upsert_cve(self, data):
        self.client.table("cves").upsert(data).execute()

    def upload_report(self, cve_id, content):
        file_path = f"{cve_id}.html"
        bucket = "reports"
        
        # [디자인 업그레이드] Modern CSS Dashboard Style
        html_template = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cve_id} Analysis Report</title>
    <style>
        :root {{ --primary: #2563eb; --danger: #dc2626; --warning: #d97706; --success: #059669; --bg: #f3f4f6; --card: #ffffff; --text: #1f2937; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; background-color: var(--bg); color: var(--text); margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ background: var(--card); padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; border-left: 5px solid var(--primary); }}
        .header h1 {{ margin: 0; font-size: 24px; color: #111; }}
        .header .meta {{ font-size: 14px; color: #6b7280; margin-top: 5px; }}
        .card {{ background: var(--card); padding: 25px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .card h2 {{ margin-top: 0; font-size: 18px; border-bottom: 2px solid #f3f4f6; padding-bottom: 10px; color: var(--primary); }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; margin-right: 5px; }}
        .badge-red {{ background-color: var(--danger); }}
        .badge-orange {{ background-color: var(--warning); }}
        .badge-green {{ background-color: var(--success); }}
        .badge-gray {{ background-color: #6b7280; }}
        code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 3px; color: #e11d48; font-family: monospace; }}
        ul {{ padding-left: 20px; }}
        li {{ margin-bottom: 5px; }}
        a {{ color: var(--primary); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .ref-box {{ background: #f8fafc; padding: 10px; border-radius: 5px; font-size: 13px; border: 1px solid #e2e8f0; }}
    </style>
</head>
<body>
    <div class="container">
        {content}
    </div>
</body>
</html>"""
        
        try:
            encoded_content = html_template.encode('utf-8-sig')
            self.client.storage.from_(bucket).upload(
                file_path, encoded_content, 
                {"content-type": "text/html; charset=utf-8", "x-upsert": "true"}
            )
        except: pass
        return self.client.storage.from_(bucket).create_signed_url(file_path, 60 * 60 * 24 * 30)