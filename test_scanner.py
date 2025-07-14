#!/usr/bin/env python3
"""
測試腳本 - 展示改進後的中文化弱點掃描器
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from WeaknessScan import VulnerabilityScanner

def test_single_cve():
    """測試單一CVE檢測"""
    scanner = VulnerabilityScanner()
    
    print("=" * 60)
    print("測試 CVE-2022-25844 Angular 依賴注入弱點檢測")
    print("=" * 60)
    
    # 載入弱點檢測腳本
    vulnerability_module = scanner.load_vulnerability_script("CVE-2022-25844")
    
    if vulnerability_module:
        print("✅ 成功載入弱點檢測腳本")
        
        # 測試目標網址
        test_url = "https://staging.tronclass.com/"
        
        print(f"\n🎯 測試目標: {test_url}")
        print("📋 開始弱點檢測...")
        
        # 執行檢測
        result = vulnerability_module.scan(scanner.session, test_url)
        
        if result:
            print(f"\n📊 檢測結果:")
            print(f"   弱點編號: CVE-2022-25844")
            print(f"   是否有弱點: {'是' if result['vulnerable'] else '否'}")
            print(f"   弱點描述: {result['description']}")
            print(f"   檢測證據: {result['evidence']}")
            print(f"   修復建議: {result['remediation']}")
        else:
            print("❌ 檢測失敗")
    else:
        print("❌ 無法載入弱點檢測腳本")

if __name__ == "__main__":
    test_single_cve()