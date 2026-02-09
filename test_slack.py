# test_slack.py
from src.notifier import SlackNotifier
import os

# 가짜 데이터 1: CCE가 없는 경우 (일반적인 케이스)
mock_data_no_cce = {
    "id": "CVE-2026-TEST-001",
    "title_ko": "Loggro Pymes 저장형 XSS 취약점 (CCE 없음)",
    "description": "이 취약점은 일반적인 XSS 취약점으로, CCE 정보가 포함되지 않은 케이스입니다. 기존 레이아웃이 잘 유지되는지 확인합니다.",
    "cvss": 5.1,
    "epss": 0.05,
    "is_kev": False,
    "cwe": ["CWE-79"],
    "cce": [], # CCE 없음
    "affected": [
        {"vendor": "Loggro", "product": "Pymes", "versions": "1.0 (단일 버전)"}
    ]
}

# 가짜 데이터 2: CCE가 있는 경우 (설정 오류 케이스)
mock_data_with_cce = {
    "id": "CVE-2026-TEST-002",
    "title_ko": "Apache HTTP Server 설정 오류 취약점 (CCE 있음)",
    "description": "이 취약점은 서버 설정 미흡으로 인해 발생하며, CCE-1234-5 설정 항목과 관련이 있습니다. 슬랙 메시지에 CCE 필드가 추가로 보여야 합니다.",
    "cvss": 7.5,
    "epss": 0.89,
    "is_kev": True,
    "cwe": ["CWE-16", "CWE-200"],
    "cce": ["CCE-1234-5", "CCE-6789-0"], # CCE 있음
    "affected": [
        {"vendor": "Apache", "product": "HTTP Server", "versions": "2.4.50 이하"}
    ]
}

def main():
    print("[*] 슬랙 UI 테스트 시작...")
    
    if not os.environ.get("SLACK_WEBHOOK_URL"):
        print("[!] SLACK_WEBHOOK_URL 환경변수가 설정되지 않았습니다.")
        return

    notifier = SlackNotifier()

    print("1. CCE 없는 메시지 발송 중...")
    notifier.send_alert(mock_data_no_cce, "테스트 발송 (CCE X)", "https://google.com")
    
    print("2. CCE 있는 메시지 발송 중...")
    notifier.send_alert(mock_data_with_cce, "테스트 발송 (CCE O)", "https://google.com")

    print("[*] 발송 완료! 슬랙을 확인해 주세요.")

if __name__ == "__main__":
    main()