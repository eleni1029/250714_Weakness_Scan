#!/usr/bin/env python3
"""
TronClass Vulnerability Scanner
Educational LMS System Security Testing Tool
Internal Security Testing with Authorized Access
"""

import os
import sys
import json
import time
import re
import importlib.util
from datetime import datetime
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import config

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})
        self.session.verify = config.ENABLE_SSL_VERIFICATION
        
        # Disable SSL warnings if verification is disabled
        if not config.ENABLE_SSL_VERIFICATION:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.results = []
        self.crawled_urls = set()
        
    def display_banner(self):
        """Display scanner banner"""
        print("=" * 70)
        print("TronClass 弱點掃描器")
        print("教育學習管理系統安全測試工具")
        print("授權內部安全測試")
        print("公司: TronClass")
        print("=" * 70)
        print()
    
    def select_vulnerabilities(self):
        """Allow user to select vulnerabilities to scan"""
        print("📋 可用的弱點檢測項目:")
        print("0. 全部弱點 (推薦進行完整掃描)")
        for i, cve in enumerate(config.AVAILABLE_CVES, 1):
            print(f"{i}. {cve}")
        
        print("\n🎯 請選擇要掃描的弱點:")
        print("   • 輸入 0 掃描所有弱點")
        print("   • 輸入單個數字掃描特定弱點 (例如: 1)")
        print("   • 輸入多個數字掃描多個弱點 (例如: 1,3,5)")
        print("   • 直接按 Enter 使用預設 (掃描所有弱點)")
        selection = input("請輸入選項: ").strip()
        
        if not selection:
            print("✅ 使用預設選項: 掃描所有弱點")
            return config.AVAILABLE_CVES
        
        if selection == "0":
            print("✅ 已選擇: 掃描所有弱點")
            return config.AVAILABLE_CVES
        
        try:
            selected_indices = [int(x.strip()) for x in selection.split(",")]
            selected_cves = []
            for idx in selected_indices:
                if 1 <= idx <= len(config.AVAILABLE_CVES):
                    selected_cves.append(config.AVAILABLE_CVES[idx - 1])
            if selected_cves:
                print(f"✅ 已選擇 {len(selected_cves)} 個弱點進行掃描")
            return selected_cves if selected_cves else config.AVAILABLE_CVES
        except ValueError:
            print("⚠️ 輸入格式無效，使用預設選項: 掃描所有弱點")
            return config.AVAILABLE_CVES
    
    def get_target_url(self):
        """Get target URL from user"""
        print(f"\n🎯 目標網址設定:")
        print(f"   預設: {config.DEFAULT_TARGET_URL}")
        print(f"   • 直接按 Enter 使用預設網址")
        print(f"   • 輸入完整網址 (例如: https://example.com)")
        print(f"   • 輸入相對路徑 (例如: /admin 或 course/list)")
        target = input("請輸入目標網址: ").strip()
        
        if not target:
            print(f"✅ 使用預設網址: {config.DEFAULT_TARGET_URL}")
            target = config.DEFAULT_TARGET_URL
        else:
            # Handle relative paths
            if target.startswith("/") or not target.startswith("http"):
                if not target.startswith("/"):
                    target = "/" + target
                full_target = urljoin(config.DEFAULT_TARGET_URL, target)
                print(f"✅ 相對路徑已轉換為: {full_target}")
                target = full_target
            else:
                # Validate URL format
                if target.startswith("http://") or target.startswith("https://"):
                    print(f"✅ 已設定目標網址: {target}")
                else:
                    print(f"⚠️ 網址格式可能不正確，建議使用 http:// 或 https:// 開頭")
                    print(f"✅ 已設定目標網址: {target}")
        
        return target
    
    def get_login_info(self):
        """Get login information from user"""
        print(f"\n🔐 登入設定:")
        print(f"   是否需要先登入系統? (某些受保護的頁面可能需要登入)")
        print(f"   • 輸入 y 或 yes 啟用登入")
        print(f"   • 輸入 n 或 no 跳過登入")
        print(f"   • 直接按 Enter 使用預設 (跳過登入)")
        need_login = input("請選擇是否需要登入 (y/n): ").strip().lower()
        
        if need_login in ['y', 'yes']:
            print(f"\n📝 登入資訊設定:")
            print(f"   預設登入網址: {config.DEFAULT_LOGIN_URL}")
            login_url = input("登入網址 (直接按 Enter 使用預設): ").strip()
            if not login_url:
                login_url = config.DEFAULT_LOGIN_URL
                print(f"✅ 使用預設登入網址: {login_url}")
            else:
                print(f"✅ 已設定登入網址: {login_url}")
            
            print(f"   預設帳號: {config.DEFAULT_USERNAME}")
            username = input("帳號 (直接按 Enter 使用預設): ").strip()
            if not username:
                username = config.DEFAULT_USERNAME
                print(f"✅ 使用預設帳號: {username}")
            else:
                print(f"✅ 已設定帳號: {username}")
            
            print(f"   預設密碼: {config.DEFAULT_PASSWORD}")
            password = input("密碼 (直接按 Enter 使用預設): ").strip()
            if not password:
                password = config.DEFAULT_PASSWORD
                print(f"✅ 使用預設密碼")
            else:
                print(f"✅ 已設定密碼")
            
            return login_url, username, password
        
        print("✅ 跳過登入，將以訪客身份進行掃描")
        return None, None, None
    
    def get_crawl_depth(self):
        """Get crawl depth from user"""
        print(f"\n🕷️ 爬取深度設定:")
        print(f"   爬取深度決定掃描器會深入網站多少層")
        print(f"   • 0: 只掃描指定的目標網址 (預設，速度最快)")
        print(f"   • 1: 掃描目標網址及其直接連結的頁面")
        print(f"   • 2-{config.MAX_CRAWL_DEPTH}: 掃描更多層級 (更全面但耗時較長)")
        print(f"   • 直接按 Enter 使用預設深度 ({config.DEFAULT_CRAWL_DEPTH})")
        depth_input = input(f"請輸入爬取深度 (0-{config.MAX_CRAWL_DEPTH}): ").strip()
        
        if not depth_input:
            print(f"✅ 使用預設爬取深度: {config.DEFAULT_CRAWL_DEPTH}")
            return config.DEFAULT_CRAWL_DEPTH
        
        try:
            depth = int(depth_input)
            if 0 <= depth <= config.MAX_CRAWL_DEPTH:
                print(f"✅ 已設定爬取深度: {depth}")
                return depth
            else:
                print(f"⚠️ 深度超出範圍，使用預設深度: {config.DEFAULT_CRAWL_DEPTH}")
                return config.DEFAULT_CRAWL_DEPTH
        except ValueError:
            print(f"⚠️ 輸入格式無效，使用預設深度: {config.DEFAULT_CRAWL_DEPTH}")
            return config.DEFAULT_CRAWL_DEPTH
    
    def login(self, login_url, username, password):
        """Perform login"""
        try:
            print(f"[資訊] 嘗試登入: {login_url}")
            
            # Get login page
            response = self.session.get(login_url, timeout=config.REQUEST_TIMEOUT)
            
            if response.status_code != 200:
                print(f"[錯誤] 無法存取登入頁面，狀態碼: {response.status_code}")
                return False
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find login form (try multiple approaches)
            form = soup.find('form')
            if not form:
                # Try to find forms with specific attributes
                form = soup.find('form', {'id': 'loginForm'}) or \
                       soup.find('form', {'class': 'login'}) or \
                       soup.find('form', {'action': re.compile(r'login', re.I)})
            
            if not form:
                print("[錯誤] 找不到登入表單")
                return False
            
            # Extract form data
            form_data = {}
            for input_field in form.find_all('input'):
                name = input_field.get('name')
                value = input_field.get('value', '')
                if name:
                    form_data[name] = value
            
            # Update with credentials - try multiple field name patterns
            username_fields = ['username', 'user', 'email', 'login', 'account', 'userid', 'loginname']
            password_fields = ['password', 'pass', 'pwd', 'passwd', 'passw']
            
            username_set = False
            password_set = False
            
            for field in username_fields:
                if field in form_data:
                    form_data[field] = username
                    username_set = True
                    break
            
            for field in password_fields:
                if field in form_data:
                    form_data[field] = password
                    password_set = True
                    break
            
            # If standard fields not found, try to detect by input types
            if not username_set or not password_set:
                for input_field in form.find_all('input'):
                    input_type = input_field.get('type', '').lower()
                    name = input_field.get('name')
                    if name:
                        if input_type == 'email' or 'email' in name.lower():
                            form_data[name] = username
                            username_set = True
                        elif input_type == 'password':
                            form_data[name] = password
                            password_set = True
            
            if not username_set or not password_set:
                print("[錯誤] 無法識別使用者名稱/密碼欄位")
                return False
            
            # Submit login
            action = form.get('action', login_url)
            method = form.get('method', 'post').lower()
            
            if method == 'get':
                login_response = self.session.get(urljoin(login_url, action), params=form_data, timeout=config.REQUEST_TIMEOUT)
            else:
                login_response = self.session.post(urljoin(login_url, action), data=form_data, timeout=config.REQUEST_TIMEOUT)
            
            # Check for successful login indicators
            success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'home', 'main']
            error_indicators = ['error', 'invalid', 'failed', 'incorrect', 'wrong']
            
            response_text = login_response.text.lower()
            
            if any(indicator in response_text for indicator in success_indicators):
                print("[資訊] 登入成功")
                return True
            elif any(indicator in response_text for indicator in error_indicators):
                print("[錯誤] 登入失敗 - 帳號或密碼錯誤")
                return False
            elif login_response.status_code in [200, 302]:
                print("[資訊] 登入嘗試完成 (狀態不明)")
                return True
            else:
                print(f"[錯誤] 登入失敗，狀態碼: {login_response.status_code}")
                return False
                
        except Exception as e:
            print(f"[錯誤] 登入失敗: {str(e)}")
            return False
    
    def crawl_urls(self, base_url, depth):
        """Crawl URLs up to specified depth"""
        if depth == 0:
            return [base_url]
        
        urls_to_scan = set([base_url])
        current_depth = 0
        
        while current_depth < depth:
            new_urls = set()
            for url in urls_to_scan - self.crawled_urls:
                try:
                    print(f"[資訊] 正在爬取: {url} (深度: {current_depth})")
                    response = self.session.get(url, timeout=config.REQUEST_TIMEOUT)
                    self.crawled_urls.add(url)
                    
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(url, href)
                            
                            # Only include URLs from the same domain
                            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                new_urls.add(full_url)
                                
                except Exception as e:
                    print(f"[錯誤] 爬取失敗 {url}: {str(e)}")
                    continue
            
            urls_to_scan.update(new_urls)
            current_depth += 1
        
        return list(urls_to_scan)
    
    def load_vulnerability_script(self, cve_id):
        """Load vulnerability detection script"""
        script_path = os.path.join(config.VULNERABILITY_LIBRARY_PATH, f"{cve_id}.py")
        
        if not os.path.exists(script_path):
            print(f"[錯誤] 找不到弱點檢測腳本: {script_path}")
            return None
        
        try:
            spec = importlib.util.spec_from_file_location(cve_id, script_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            print(f"[錯誤] 載入弱點檢測腳本失敗 {cve_id}: {str(e)}")
            return None
    
    def scan_vulnerability(self, cve_id, urls):
        """Scan for specific vulnerability"""
        print(f"\n[資訊] 正在掃描弱點: {cve_id}...")
        
        vulnerability_module = self.load_vulnerability_script(cve_id)
        if not vulnerability_module:
            return
        
        for url in urls:
            try:
                print(f"[資訊] 測試 {cve_id} 於 {url}")
                
                # Call the vulnerability detection function
                if hasattr(vulnerability_module, 'scan'):
                    result = vulnerability_module.scan(self.session, url)
                    if result:
                        self.results.append({
                            'cve_id': cve_id,
                            'url': url,
                            'vulnerable': result.get('vulnerable', False),
                            'evidence': result.get('evidence', ''),
                            'description': result.get('description', ''),
                            'remediation': result.get('remediation', ''),
                            'timestamp': datetime.now().isoformat()
                        })
                
            except Exception as e:
                print(f"[錯誤] 掃描 {cve_id} 於 {url} 時發生錯誤: {str(e)}")
    
    def generate_report(self):
        """Generate vulnerability report"""
        report_filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write("TronClass 弱點掃描報告\n")
            f.write("=" * 50 + "\n")
            f.write(f"報告生成時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"公司: {config.COMPANY_NAME}\n")
            f.write(f"授權測試: {config.AUTHORIZED_TESTING}\n")
            f.write(f"內部安全測試: {config.INTERNAL_SECURITY_TESTING}\n")
            f.write("\n")
            
            # Summary
            total_scans = len(self.results)
            vulnerabilities_found = sum(1 for r in self.results if r['vulnerable'])
            
            f.write("掃描摘要\n")
            f.write("-" * 20 + "\n")
            f.write(f"總掃描次數: {total_scans}\n")
            f.write(f"發現弱點數量: {vulnerabilities_found}\n")
            f.write(f"安全狀態: {'發現弱點' if vulnerabilities_found > 0 else '安全'}\n")
            f.write("\n")
            
            # Detailed results
            f.write("詳細結果\n")
            f.write("-" * 20 + "\n")
            
            for result in self.results:
                f.write(f"CVE 編號: {result['cve_id']}\n")
                f.write(f"目標網址: {result['url']}\n")
                f.write(f"是否有弱點: {'是' if result['vulnerable'] else '否'}\n")
                f.write(f"弱點描述: {result['description']}\n")
                if result['vulnerable']:
                    f.write(f"證據: {result['evidence']}\n")
                    f.write(f"修復建議: {result['remediation']}\n")
                f.write(f"掃描時間: {result['timestamp']}\n")
                f.write("-" * 40 + "\n")
        
        print(f"\n[資訊] 報告已生成: {report_filename}")
        return report_filename
    
    def run(self):
        """Main scanner execution"""
        self.display_banner()
        
        # Get user inputs
        selected_cves = self.select_vulnerabilities()
        target_url = self.get_target_url()
        login_url, username, password = self.get_login_info()
        crawl_depth = self.get_crawl_depth()
        
        print(f"\n🚀 開始弱點掃描...")
        print(f"[資訊] 目標網址: {target_url}")
        print(f"[資訊] 弱點檢測項目: {len(selected_cves)} 個")
        print(f"[資訊] 爬取深度: {crawl_depth}")
        
        # Perform login if needed
        if login_url and username and password:
            if not self.login(login_url, username, password):
                print("[錯誤] 登入失敗，將繼續以訪客身份進行掃描...")
        
        # Crawl URLs
        print(f"\n🕷️ 開始爬取網址...")
        urls_to_scan = self.crawl_urls(target_url, crawl_depth)
        print(f"[資訊] 找到 {len(urls_to_scan)} 個網址待掃描")
        
        # Scan vulnerabilities
        print(f"\n🔍 開始弱點掃描...")
        for cve_id in selected_cves:
            self.scan_vulnerability(cve_id, urls_to_scan)
        
        # Generate report
        report_file = self.generate_report()
        
        print(f"\n✅ 掃描完成!")
        print(f"[資訊] 報告已儲存至: {report_file}")
        
        # Display summary
        vulnerabilities_found = sum(1 for r in self.results if r['vulnerable'])
        if vulnerabilities_found > 0:
            print(f"⚠️ 警告: 發現 {vulnerabilities_found} 個弱點!")
        else:
            print("🔒 [資訊] 未發現弱點，系統安全狀態良好。")

if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n[資訊] 掃描已被使用者中斷")
    except Exception as e:
        print(f"[錯誤] 發生未預期的錯誤: {str(e)}")