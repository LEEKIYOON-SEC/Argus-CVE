import requests
import json
from datetime import datetime, timedelta
from src.config import Config

class ArgusWatcher:
    def __init__(self):
        self.cve_api_url = "https://cveawg.mitre.org/api/cve/"
        self.kev_list = self._load_kev_data()

    def _load_kev_data(self):
        """CISA KEV 데이터 로드"""
        try:
            print("[Watcher] Fetching CISA KEV list...")
            res = requests.get(Config.CISA_KEV_URL)
            if res.status_code == 200:
                data = res.json()
                return set(vuln['cveID'] for vuln in data['vulnerabilities'])
        except Exception as e:
            print(f"[Watcher] Failed to load KEV: {e}")
        return set()

    def fetch_latest_cves(self, hours=2):
        """CVE.org API에서 최근 변경된 CVE 수집"""
        now = datetime.utcnow()
        start_date = (now - timedelta(hours=hours)).isoformat()
        
        params = {
            "time_modified_gt": start_date
        }

        try:
            print(f"[Watcher] Fetching CVE.org data since {start_date}...")
            res = requests.get(self.cve_api_url, params=params)
            
            if res.status_code != 200:
                print(f"[Watcher] CVE.org API Error: {res.status_code}")
                return []
            
            data = res.json()
            cve_items = data.get("cveRecords", [])
            print(f"[Watcher] Found {len(cve_items)} CVEs from CVE.org.")
            
            parsed_list = []
            for item in cve_items:
                parsed = self.parse_cve_item(item)
                if parsed:
                    parsed_list.append(parsed)
                    
            return parsed_list

        except Exception as e:
            print(f"[Watcher] Error fetching CVEs: {e}")
            return []

    def parse_cve_item(self, item):
        """CVE JSON 5.0 Parsing (CVSS 4.0 Support)"""
        try:
            metadata = item.get("cveMetadata", {})
            containers = item.get("containers", {}).get("cna", {})
            
            if metadata.get("state") != "PUBLISHED":
                return None
            
            cve_id = metadata.get("cveId")
            
            descriptions = containers.get("descriptions", [])
            desc_text = "No description"
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value")
                    break
            
            # Metrics Parsing (Priority: 4.0 > 3.1 > 3.0)
            metrics_list = containers.get("metrics", [])
            
            final_score = 0.0
            final_ver = "UNKNOWN"
            final_vector = ""
            final_severity = "UNKNOWN"
            
            found_ver_num = 0.0
            
            for metric in metrics_list:
                # Check CVSS 4.0
                if "cvssV4_0" in metric:
                    cvss = metric["cvssV4_0"]
                    if 4.0 > found_ver_num:
                        final_score = cvss.get("baseScore", 0.0)
                        final_ver = "4.0"
                        final_vector = cvss.get("vectorString", "")
                        final_severity = cvss.get("baseSeverity", "UNKNOWN")
                        found_ver_num = 4.0
                        
                # Check CVSS 3.1
                elif "cvssV3_1" in metric:
                    cvss = metric["cvssV3_1"]
                    if 3.1 > found_ver_num:
                        final_score = cvss.get("baseScore", 0.0)
                        final_ver = "3.1"
                        final_vector = cvss.get("vectorString", "")
                        final_severity = cvss.get("baseSeverity", "UNKNOWN")
                        found_ver_num = 3.1
                        
                # Check CVSS 3.0
                elif "cvssV3_0" in metric:
                    cvss = metric["cvssV3_0"]
                    if 3.0 > found_ver_num:
                        final_score = cvss.get("baseScore", 0.0)
                        final_ver = "3.0"
                        final_vector = cvss.get("vectorString", "")
                        final_severity = cvss.get("baseSeverity", "UNKNOWN")
                        found_ver_num = 3.0

            assigner = metadata.get("assignerShortName", "UNKNOWN")

            return {
                "cve_id": cve_id,
                "description": desc_text,
                "cvss_score": final_score,
                "cvss_version": final_ver,
                "cvss_vector": final_vector,
                "severity": final_severity,
                "cve_state": metadata.get("state"),
                "published_at": metadata.get("datePublished"),
                "updated_at": metadata.get("dateUpdated"),
                "assigner": assigner
            }
            
        except Exception as e:
            print(f"[Watcher] Error parsing item: {e}")
            return None

    def check_github_poc(self, cve_id):
        """GitHub Search API for PoC"""
        from src.config import Config
        
        query = f'"{cve_id}" AND ("exploit" OR "poc" OR "rce")'
        url = f"https://api.github.com/search/repositories?q={query}"
        headers = {
            "Authorization": f"Bearer {Config.GH_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            res = requests.get(url, headers=headers)
            if res.status_code == 200:
                data = res.json()
                if data['total_count'] > 0:
                    return True, data['items'][0]['html_url']
            elif res.status_code == 403:
                print("[Watcher] GitHub Rate Limit Hit!")
                
        except Exception as e:
            print(f"[Watcher] GitHub Search Error: {e}")
            
        return False, None