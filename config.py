import os

SYSTEM_NAME = "Argus-AI-Threat Intelligence"

GH_TOKEN = os.environ.get("GH_TOKEN")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
VULNCHECK_API_KEY = os.environ.get("VULNCHECK_API_KEY")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

EPSS_IMMEDIATE = 0.1
EPSS_CONDITIONAL = 0.01
CVSS_HIGH = 7.0

DISCOVERY_LOOKBACK_MINUTES = int(os.environ.get("DISCOVERY_LOOKBACK_MINUTES", "120"))

RULES_CACHE_DIR = os.environ.get("RULES_CACHE_DIR", "rules_cache")

# 실제 운영 환경 Suricata 버전 맞춰 설정 변경
ETOPEN_SURICATA_VERSION = os.environ.get("ETOPEN_SURICATA_VERSION", "7.0.3")

GITHUB_RULE_ALLOWLIST = [
    "SigmaHQ/sigma",
    "Neo23x0/sigma",
    "Yara-Rules/rules",
]

ENABLE_IDS_CONTAINER_VALIDATION = True
ENABLE_SNORT2_VALIDATION = True
ENABLE_SNORT3_VALIDATION = True
ENABLE_SURICATA_VALIDATION = True
