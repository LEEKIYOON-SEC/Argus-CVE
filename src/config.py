import json
import os

# [1] AI 모델 설정
MODEL_PHASE_0 = "gemma-3-27b-it"        # 리포트/번역용 (기존)
MODEL_PHASE_1 = "openai/gpt-oss-120b"   # [Phase 1] 심층 분석 및 룰 생성용

# [Phase 1] Groq High Reasoning 파라미터
GROQ_PARAMS = {
    "temperature": 0.6,             
    "top_p": 0.95,                  
    "max_completion_tokens": 4096,  
    "reasoning_effort": "high",     # [핵심] 고추론 활성화
    "response_format": {"type": "json_object"} # Analyzer용 (RuleManager는 오버라이드)
}

# [2] 감시 대상 로드 (assets.json)
def load_assets():
    file_path = "assets.json"
    default_rules = [{"vendor": "*", "product": "*"}]
    if not os.path.exists(file_path):
        return default_rules
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("active_rules", default_rules)
    except:
        return default_rules

TARGET_ASSETS = load_assets()