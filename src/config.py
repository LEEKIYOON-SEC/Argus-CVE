import os
from datetime import datetime, timedelta

class Config:
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
    GH_TOKEN = os.getenv("GH_TOKEN")
    NVD_API_KEY = os.getenv("NVD_API_KEY")

    # 초기 설정: 모든 벤더('*') 수집. 나중에 ["microsoft", "adobe"] 등으로 변경.
    TARGET_VENDORS = ["*"] 
    
    CRITICAL_CVSS = 9.0
    HIGH_CVSS = 7.0
    EPSS_THRESHOLD = 0.1  # 10% 이상 확률이면 위험
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    @staticmethod
    def is_target_vendor(vendor_name):
        """벤더 필터링 로직"""
        if not vendor_name:
            return False
            
        if "*" in Config.TARGET_VENDORS:
            return True
            
        vendor_lower = vendor_name.lower()
        for target in Config.TARGET_VENDORS:
            if target.lower() in vendor_lower:
                return True
        return False