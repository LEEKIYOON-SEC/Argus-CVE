import os
import json
from groq import Groq
import config

class Analyzer:
    def __init__(self):
        self.client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1

    def analyze_cve(self, cve_data):
        """
        CVE 심층 분석 (High Reasoning 적용)
        """
        # [중요] System Prompt 배제 -> User Prompt에 통합
        prompt = f"""
        You are a Senior Security Analyst. Analyze the following CVE deeply.
        
        [Context]
        CVE-ID: {cve_data['id']}
        Description: {cve_data['description']}
        CWE: {', '.join(cve_data.get('cwe', []))}
        CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
        Affected Info: {json.dumps(cve_data.get('affected', []))}

        [Tasks]
        1. **Root Cause**: Identify the technical root cause (e.g., buffer overflow in parser X).
        2. **Kill Chain Scenario**: Describe the attack flow based on MITRE ATT&CK standards (Initial Access -> Execution -> Impact).
        3. **Business Impact**: Assess the impact on CIA (Confidentiality, Integrity, Availability) in business terms.
        4. **Mitigation**: Suggest specific remediation steps. If a version is mentioned like "less than 1.2.3", infer the fixed version (e.g., "Update to 1.2.3 or later").
        5. **Rule Feasibility**: Determine if we can create a specific Snort/Yara rule. 
           - Set to true ONLY IF specific indicators (file paths, parameters, magic bytes, specific function names) are present in the description.
           - Set to false if the description is generic (e.g., "unspecified vulnerability").

        [Output Format]
        Return ONLY a raw JSON object with these keys: "root_cause", "scenario", "impact", "mitigation" (list), "rule_feasibility" (boolean).
        """

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt} # [지침 준수] User 메시지만 사용
                ],
                temperature=config.GROQ_PARAMS["temperature"],
                top_p=config.GROQ_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_PARAMS["max_completion_tokens"],
                # reasoning_effort=config.GROQ_PARAMS["reasoning_effort"], # 라이브러리 지원 시 주석 해제 (현재 Groq SDK 버전에 따라 다를 수 있음)
                response_format=config.GROQ_PARAMS["response_format"]
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"[ERR] Analyzer Failed: {e}")
            return {
                "root_cause": "분석 실패",
                "scenario": "자동 분석을 수행할 수 없습니다.",
                "impact": "정보 없음",
                "mitigation": ["제조사 권고문 참조"],
                "rule_feasibility": False
            }