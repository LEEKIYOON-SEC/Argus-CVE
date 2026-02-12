import os
import requests
import tarfile
import io
import re
from groq import Groq
import config

class RuleManager:
    def __init__(self):
        self.gh_token = os.environ.get("GH_TOKEN")
        self.groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1
        self.snort_cache = []  # 메모리 캐시

    def _search_github(self, repo, query):
        """GitHub Code Search API"""
        url = f"https://api.github.com/search/code?q=repo:{repo} {query}"
        headers = {"Authorization": f"token {self.gh_token}", "Accept": "application/vnd.github.v3+json"}
        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200 and res.json().get('total_count', 0) > 0:
                item = res.json()['items'][0]
                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                return requests.get(raw_url).text
            return None
        except: return None

    def _fetch_snort_rules(self, cve_id):
        """Snort Community & ET Open 직접 다운로드 및 메모리 검색"""
        found_rule = None
        
        # 1. Snort Community Rules (.tar.gz)
        if not self.snort_cache:
            try:
                # print("[INFO] Downloading Snort Community Rules...")
                res = requests.get("https://www.snort.org/downloads/community/community-rules.tar.gz", timeout=15)
                if res.status_code == 200:
                    with tarfile.open(fileobj=io.BytesIO(res.content), mode="r:gz") as tar:
                        for member in tar.getmembers():
                            if "community.rules" in member.name:
                                f = tar.extractfile(member)
                                content = f.read().decode('utf-8', errors='ignore')
                                self.snort_cache.append(content)
                                break
            except Exception as e:
                print(f"[WARN] Failed to fetch Snort Community: {e}")

            # 2. ET Open Rules (.rules text)
            try:
                # print("[INFO] Downloading ET Open Rules...")
                res = requests.get("https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules", timeout=15)
                if res.status_code == 200:
                    self.snort_cache.append(res.text)
            except Exception as e:
                print(f"[WARN] Failed to fetch ET Open: {e}")

        # 캐시된 룰에서 검색
        for ruleset in self.snort_cache:
            for line in ruleset.splitlines():
                if cve_id in line and "alert" in line and not line.strip().startswith("#"):
                    return line.strip()
        
        return None

    def _validate_syntax(self, rule_type, code):
        """AI 생성 룰 문법 검증 (Safety First)"""
        if not code: return False
        try:
            if rule_type == "Snort":
                if not re.match(r'^(alert|log|pass|drop|reject|sdrop)\s', code.strip()): return False
                if code.count('(') != code.count(')'): return False # 괄호 짝
                if "msg:" not in code or "sid:" not in code: return False
                return True
            elif rule_type == "Yara":
                if not code.strip().startswith("rule "): return False
                if code.count('{') != code.count('}'): return False
                if "condition:" not in code: return False
                return True
            elif rule_type == "Sigma":
                required = ["title:", "logsource:", "detection:", "condition:"]
                for req in required:
                    if req not in code: return False
                return True
        except: return False
        return False

    def _generate_ai_rule(self, rule_type, cve_data):
        """Groq High Reasoning 룰 생성"""
        prompt = f"""
        You are a Senior Security Engineer. Write a valid {rule_type} detection rule for {cve_data['id']}.
        
        [Context]
        Description: {cve_data['description']}
        Vector: {cve_data['cvss_vector']}

        [Requirements]
        - **Snort**: Must start with 'alert tcp ...', include 'msg', 'sid', 'rev'.
        - **Yara**: Must include 'meta', 'strings', 'condition'.
        - **Sigma**: Must be valid YAML with 'title', 'logsource', 'detection', 'condition'.
        - Output ONLY the code block. No markdown, no explanations.
        - If you cannot create a valid rule due to lack of information, return 'SKIP'.
        """
        
        try:
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}], # [지침 준수] User 메시지만 사용
                temperature=config.GROQ_PARAMS["temperature"],
                top_p=config.GROQ_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_PARAMS["max_completion_tokens"],
                # reasoning_effort=config.GROQ_PARAMS["reasoning_effort"]
            )
            content = response.choices[0].message.content.strip()
            content = re.sub(r"```[a-z]*\n|```", "", content).strip() # 마크다운 제거
            
            if content == "SKIP": return None

            # [검증]
            if self._validate_syntax(rule_type, content):
                return content
            else:
                print(f"[WARN] 🚨 Syntax Error in AI {rule_type} Rule. Discarded.\nCode: {content[:50]}...")
                return None
        except Exception as e:
            print(f"[ERR] AI Rule Gen Failed: {e}")
            return None

    def get_rules(self, cve_data, feasibility):
        rules = {"sigma": None, "snort": None, "yara": None}
        cve_id = cve_data['id']

        # 1. Sigma (Always)
        public_sigma = self._search_github("SigmaHQ/sigma", f"{cve_id} filename:.yml")
        if public_sigma:
            rules['sigma'] = {"code": public_sigma, "source": "Public (SigmaHQ)"}
        else:
            ai_sigma = self._generate_ai_rule("Sigma", cve_data)
            if ai_sigma:
                rules['sigma'] = {"code": ai_sigma, "source": "AI Generated (Verified)"}

        # 2. Snort (Conditional)
        public_snort = self._fetch_snort_rules(cve_id)
        if public_snort:
            rules['snort'] = {"code": public_snort, "source": "Public (Snort/ET)"}
        elif feasibility:
            ai_snort = self._generate_ai_rule("Snort", cve_data)
            if ai_snort:
                rules['snort'] = {"code": ai_snort, "source": "AI Generated (Verified)"}

        # 3. Yara (Conditional)
        public_yara = self._search_github("Yara-Rules/rules", f"{cve_id} filename:.yar")
        if public_yara:
            rules['yara'] = {"code": public_yara, "source": "Public (Yara-Rules)"}
        elif feasibility:
            ai_yara = self._generate_ai_rule("Yara", cve_data)
            if ai_yara:
                rules['yara'] = {"code": ai_yara, "source": "AI Generated (Verified)"}

        return rules