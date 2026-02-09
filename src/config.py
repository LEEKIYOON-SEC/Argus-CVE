import json
import os

# [1] AI 모델 설정 (User Fixed)
# Phase 0: 리포트/요약용 (Smart Scout Model)
MODEL_PHASE_0 = "meta-llama/llama-4-scout-17b-16e-instruct"

# Phase 1: 룰 생성/심층 대응용 (Expert Model - Reserved)
MODEL_PHASE_1 = "openai/gpt-oss-120b"

# [2] 감시 대상 로드 (assets.json)
def load_assets():
    file_path = "assets.json"
    # 파일이 없거나 에러 시 기본값: 전체 허용
    default_rules = [{"vendor": "*", "product": "*"}]
    
    if not os.path.exists(file_path):
        print(f"[WARN] {file_path} not found. Defaulting to wildcard (*).")
        return default_rules
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # "active_rules" 키 안에 있는 리스트만 반환
            return data.get("active_rules", default_rules)
    except Exception as e:
        print(f"[ERR] Failed to parse assets.json: {e}")
        return default_rules

# 모듈 로드 시점에 실행
TARGET_ASSETS = load_assets()