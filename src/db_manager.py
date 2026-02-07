import os
from supabase import create_client, Client
from src.config import Config

class ArgusDB:
    def __init__(self):
        url: str = Config.SUPABASE_URL
        key: str = Config.SUPABASE_KEY
        
        if not url or not key:
            raise ValueError("Supabase URL or Key is missing!")
            
        self.supabase: Client = create_client(url, key)

    def cve_exists(self, cve_id: str):
        """이미 DB에 존재하는 CVE인지 확인"""
        response = self.supabase.table("vuln_cves").select("cve_id").eq("cve_id", cve_id).execute()
        return len(response.data) > 0

    def upsert_cve(self, cve_data: dict):
        """CVE 기본 정보 저장/업데이트"""
        try:
            data, count = self.supabase.table("vuln_cves").upsert(cve_data).execute()
            return data
        except Exception as e:
            print(f"[Argus-DB] Error upserting CVE {cve_data.get('cve_id')}: {e}")
            return None

    def upsert_threat_intel(self, intel_data: dict):
        """위협 정보 저장 (KEV, EPSS, PoC 등)"""
        try:
            
            existing = self.supabase.table("threat_intel").select("id").eq("cve_id", intel_data['cve_id']).execute()
            
            if existing.data:
                self.supabase.table("threat_intel").update(intel_data).eq("cve_id", intel_data['cve_id']).execute()
            else:
                self.supabase.table("threat_intel").insert(intel_data).execute()
                
        except Exception as e:
            print(f"[Argus-DB] Error saving Threat Intel: {e}")

    def save_rule(self, rule_data: dict):
        """생성된 룰 저장"""
        try:
            self.supabase.table("generated_rules").insert(rule_data).execute()
        except Exception as e:
            print(f"[Argus-DB] Error saving Rule: {e}")