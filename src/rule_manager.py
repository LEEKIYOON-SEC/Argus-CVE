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
        self.snort_cache = []

    def _search_github(self, repo, query):
        print(f"[🔍 검증 로그] GitHub 검색 시작: repo:{repo} {query}")
        url = f"https://api.github.com/search/code?q=repo:{repo} {query}"
        headers = {"Authorization": f"token {self.gh_token}", "Accept": "application/vnd.github.v3+json"}
        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200 and res.json().get('total_count', 0) > 0:
                item = res.json()['items'][0]
                print(f"[✅ 검증 로그] GitHub 룰 발견! URL: {item['html_url']}")
                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                return requests.get(raw_url).text
            print(f"[❌ 검증 로그] GitHub 룰 없음 ({repo})")
            return None
        except Exception as e: 
            print(f"[ERR] GitHub Search Err: {e}")
            return None

    def _fetch_snort_rules(self, cve_id):
        print(f"[🔍 검증 로그] Snort/ET Open 룰셋 메모리 검색 시작: {cve_id}")
        if not self.snort_cache:
            try:
                # print("[INFO] Snort Community Rules 다운로드 중...")
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

            try:
                # print("[INFO] ET Open Rules 다운로드 중...")
                res = requests.get("https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules", timeout=15)
                if res.status_code == 200:
                    self.snort_cache.append(res.text)
            except Exception as e:
                print(f"[WARN] Failed to fetch ET Open: {e}")

        for i, ruleset in enumerate(self.snort_cache):
            source_name = "Snort Community" if i == 0 else "ET Open"
            for line in ruleset.splitlines():
                if cve_id in line and "alert" in line and not line.strip().startswith("#"):
                    print(f"[✅ 검증 로그] {source_name}에서 룰 발견!")
                    return line.strip()
        
        print("[❌ 검증 로그] Snort/ET Open에서 룰을 찾지 못함.")
        return None

    def _validate_syntax(self, rule_type, code):
        """AI 생성 룰 문법 검증 (정규식 기반 정밀 검증)"""
        if not code: return False
        try:
            if rule_type == "Snort":
                # 시작: alert/log/drop + 프로토콜(tcp/udp/ip/icmp)
                if not re.match(r'^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s', code.strip(), re.IGNORECASE): 
                    print("[DEBUG] Snort Header Mismatch")
                    return False
                if code.count('(') != code.count(')'): 
                    print("[DEBUG] Snort Parentheses Mismatch")
                    return False
                if "msg:" not in code or "sid:" not in code: 
                    print("[DEBUG] Snort Missing 'msg' or 'sid'")
                    return False
                return True
            
            elif rule_type == "Yara":
                # rule + 룰이름 + {
                if not re.match(r'^rule\s+[a-zA-Z0-9_]+\s*\{', code.strip(), re.IGNORECASE): 
                    print("[DEBUG] Yara Header Mismatch")
                    return False
                if code.count('{') != code.count('}'): 
                    print("[DEBUG] Yara Braces Mismatch")
                    return False
                if "condition:" not in code: 
                    print("[DEBUG] Yara Missing 'condition'")
                    return False
                return True
            
            elif rule_type == "Sigma":
                # YAML 필수 키 (대소문자/공백 유연하게)
                # title:, logsource:, detection:, condition:
                checks = [
                    (r'title\s*:', "Title"),
                    (r'logsource\s*:', "Logsource"),
                    (r'detection\s*:', "Detection"),
                    (r'condition\s*:', "Condition")
                ]
                for pattern, name in checks:
                    if not re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                        print(f"[DEBUG] Sigma Missing '{name}'")
                        return False
                return True
                
        except Exception as e:
            print(f"[ERR] Validation Logic Error: {e}")
            return False
        return False

    def _generate_ai_rule(self, rule_type, cve_data):
        print(f"[🧠 검증 로그] AI({rule_type}) 생성 시도 중...")
        
        # [수정] 프롬프트를 매우 구체적인 템플릿 형태로 변경하여 문법 에러 원천 차단
        prompt = f"""
        You are a Senior Security Engineer. Write a valid {rule_type} detection rule for {cve_data['id']}.
        
        [Context]
        Description: {cve_data['description']}
        Vector: {cve_data['cvss_vector']}

        [Strict Output Rules]
        - Output ONLY the raw code block. No markdown, no comments, no explanations.
        - If information is insufficient, return 'SKIP'.

        [Template Requirement - Follow EXACTLY]
        """

        if rule_type == "Snort":
            prompt += """
            - Format: alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"..."; flow:...; content:"..."; sid:1000001; rev:1;)
            - Ensure parenthesis are balanced.
            """
        elif rule_type == "Yara":
            prompt += """
            - Format:
              rule CVE_... {
                  meta: ...
                  strings: ...
                  condition: ...
              }
            """
        elif rule_type == "Sigma":
            prompt += """
            - Format (YAML):
              title: ...
              status: experimental
              logsource:
                category: webserver
                product: apache (adjust based on CVE)
              detection:
                selection:
                  ...
                condition: selection
            """

        try:
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_PARAMS["temperature"],
                top_p=config.GROQ_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_PARAMS["max_completion_tokens"],
                reasoning_effort=config.GROQ_PARAMS["reasoning_effort"]
            )
            
            content = response.choices[0].message.content.strip()
            content = re.sub(r"```[a-z]*\n|```", "", content).strip()
            
            if content == "SKIP": 
                print(f"[⛔ 검증 로그] AI가 {rule_type} 생성을 SKIP 함 (정보 부족)")
                return None

            if self._validate_syntax(rule_type, content):
                print(f"[✅ 검증 로그] AI {rule_type} 룰 생성 및 검증 성공")
                return content
            else:
                # 검증 실패 시 생성된 코드를 출력하여 디버깅 가능하게 함
                print(f"\n[WARN] 🚨 Syntax Error in AI {rule_type} Rule. Discarded.")
                print("="*20 + " [FAILED CODE START] " + "="*20)
                print(content)
                print("="*20 + " [FAILED CODE END] " + "="*20 + "\n")
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
        else:
             print(f"[ℹ️ 검증 로그] Snort 생성 생략 (Feasibility: False)")

        # 3. Yara (Conditional)
        public_yara = self._search_github("Yara-Rules/rules", f"{cve_id} filename:.yar")
        if public_yara:
            rules['yara'] = {"code": public_yara, "source": "Public (Yara-Rules)"}
        elif feasibility:
            ai_yara = self._generate_ai_rule("Yara", cve_data)
            if ai_yara:
                rules['yara'] = {"code": ai_yara, "source": "AI Generated (Verified)"}
        else:
             print(f"[ℹ️ 검증 로그] Yara 생성 생략 (Feasibility: False)")

        return rules