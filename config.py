"""
TronClass 弱點掃描器設定檔
教育學習管理系統安全測試
"""

# 預設登入憑證
DEFAULT_USERNAME = "weaknesstester"
DEFAULT_PASSWORD = "test123"

# 預設目標網址
DEFAULT_LOGIN_URL = "https://staging.tronclass.com/login"
DEFAULT_TARGET_URL = "https://staging.tronclass.com/management/course#/?pageIndex=1"

# 爬取設定
DEFAULT_CRAWL_DEPTH = 0  # 預設爬取深度
MAX_CRAWL_DEPTH = 5      # 最大爬取深度

# 請求設定
REQUEST_TIMEOUT = 30     # 請求逾時時間（秒）
MAX_RETRIES = 3         # 最大重試次數
USER_AGENT = "Mozilla/5.0 (TronClass Security Scanner) Chrome/91.0.4472.124"

# 報告設定
REPORT_FORMAT = "txt"
REPORT_FILENAME = "vulnerability_report.txt"

# 掃描器設定
ENABLE_SSL_VERIFICATION = False  # 針對使用自簽憑證的測試環境停用SSL驗證
FOLLOW_REDIRECTS = True          # 跟隨重導向
MAX_CONCURRENT_REQUESTS = 10     # 最大並行請求數

# 弱點檢測設定
VULNERABILITY_LIBRARY_PATH = "./library"  # 弱點檢測腳本路徑

# 可用的CVE檢測項目
AVAILABLE_CVES = [
    "CVE-2025-2336",  # 一般網路應用程式弱點
    "CVE-2025-0716",  # 認證繞過弱點
    "CVE-2024-8372",  # 跨站指令碼攻擊(XSS)
    "CVE-2024-8373",  # SQL注入攻擊
    "CVE-2024-33665", # 檔案上傳弱點
    "CVE-2024-21490", # AngularJS範本注入
    "CVE-2023-26118", # Angular相依性弱點
    "CVE-2023-26117", # Angular表單弱點
    "CVE-2023-26116", # Angular路由弱點
    "CVE-2022-25869", # 原型污染弱點
    "CVE-2022-25844"  # Angular相依性注入弱點
]

# 日誌設定
LOG_LEVEL = "INFO"
LOG_FILE = "scanner.log"

# 公司資訊
COMPANY_NAME = "TronClass"
AUTHORIZED_TESTING = True        # 授權測試
INTERNAL_SECURITY_TESTING = True # 內部安全測試