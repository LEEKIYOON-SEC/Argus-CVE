import requests
import datetime
import pytz
import os
import re

class Collector:
    def __init__(self):
        self.kev_set = set()
        self.epss_cache = {}
        # GitHub Actions 자동 토큰 사용
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }

    def fetch_kev(self):
        """CISA KEV 카탈로그 로드"""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json()
                self.kev_set = {vuln['cveID'] for vuln in data['vulnerabilities']}
                print(f"[INFO] Loaded {len(self.kev_set)} KEVs")
        except Exception as e:
            print(f"[WARN] Failed to fetch KEV: {e}")

    def fetch_epss(self, cve_ids):
        """First.org에서 EPSS 일괄 조회"""
        if not cve_ids: return
        chunk_size = 50
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            ids_str = ",".join(chunk)
            url = f"https://api.first.org/data/v1/epss?cve={ids_str}"
            try:
                res = requests.get(url, timeout=10)
                if res.status_code == 200:
                    data = res.json().get('data', [])
                    for item in data:
                        self.epss_cache[item['cve']] = float(item['epss'])
            except Exception as e:
                print(f"[WARN] EPSS fetch failed: {e}")

    def fetch_recent_cves(self, hours=2):
        """GitHub cvelistV5 커밋 추적"""
        now = datetime.datetime.now(pytz.UTC)
        since_time = now - datetime.timedelta(hours=hours)
        since_str = since_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        url = f"https://api.github.com/repos/CVEProject/cvelistV5/commits?since={since_str}"
        print(f"\n[DEBUG] Tracking Changes from: {url}")

        try:
            res = requests.get(url, headers=self.headers, timeout=10)
            if res.status_code == 200:
                commits = res.json()
                print(f"[DEBUG] Found {len(commits)} commits")
                cve_ids = set()
                
                for commit in commits:
                    commit_url = commit['url']
                    c_res = requests.get(commit_url, headers=self.headers, timeout=5)
                    if c_res.status_code == 200:
                        files = c_res.json().get('files', [])
                        for f in files:
                            filename = f['filename']
                            if filename.endswith(".json") and "CVE-" in filename:
                                match = re.search(r'(CVE-\d{4}-\d{4,7})', filename)
                                if match:
                                    cve_ids.add(match.group(1))
                return list(cve_ids)
            else:
                print(f"[DEBUG] Error Response: {res.text}")
                return []
        except Exception as e:
            print(f"[ERR] Failed to fetch GitHub Commits: {e}")
            return []

    def enrich_cve(self, cve_id):
        """CVE 상세 정보 조회 (Raw JSON)"""
        try:
            parts = cve_id.split('-')
            year = parts[1]
            id_num = parts[2]
            if len(id_num) < 4: group_dir = "0xxx"
            else: group_dir = id_num[:-3] + "xxx"

            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"
            res = requests.get(raw_url, timeout=5)
            data = {"id": cve_id, "cvss": 0.0, "description": "N/A"}

            if res.status_code == 200:
                json_data = res.json()
                try:
                    desc_list = json_data.get('containers', {}).get('cna', {}).get('descriptions', [])
                    for d in desc_list:
                        if d.get('lang') == 'en':
                            data['description'] = d.get('value')
                            break
                except: pass
                try:
                    metrics = json_data.get('containers', {}).get('cna', {}).get('metrics', [])
                    for m in metrics:
                        if 'cvssV3_1' in m:
                            data['cvss'] = m['cvssV3_1'].get('baseScore', 0.0)
                            break
                except: pass
            return data
        except:
            return {"id": cve_id, "cvss": 0.0, "description": "Error fetching details"}