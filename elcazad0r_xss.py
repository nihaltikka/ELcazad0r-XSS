import sys
import os
import html
import requests
import json
import datetime
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
time.sleep(1)
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException, TimeoutException
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PyQt5.QtWidgets import (
    QSplashScreen,
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QProgressBar,
    QTabWidget, QListWidget, QMessageBox, QCheckBox, QListWidgetItem,
    QFileDialog, QGroupBox, QFormLayout, QGraphicsScene, QGraphicsView,
    QGraphicsTextItem, QGraphicsRectItem, QDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QTimer
from PyQt5.QtGui import QDesktopServices, QPainter, QFont, QBrush, QColor, QImage, QPixmap, QIcon
import psutil
import datetime

class XSSScannerThread(QThread):
    update_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)
    telegram_signal = pyqtSignal(str, str)  # URL, vulnerability type
    save_state_signal = pyqtSignal(dict)  # Save current scan state
    tab_log_signal = pyqtSignal(str, str)  # Tab name, log message
    alert_count_signal = pyqtSignal(int)   # Alert count update
    url_index_signal = pyqtSignal(int, int)  # Current URL index, total URLs

    def __init__(self, target_urls, payloads, use_headless, telegram_config=None, resume_data=None, test_config=None):
        super().__init__()
        self.target_urls = target_urls
        self.payloads = payloads
        self.use_headless = use_headless
        self.telegram_config = telegram_config
        self.running = True
        self.paused = False
        self.driver = None
        self.resume_data = resume_data or {}
        self.alert_count = 0
        # Default test configuration (all tests enabled)
        self.test_config = test_config or {
            'query_params': True,
            'path_segments': True,
            'file_extensions': True,
            'post_params': True,
            'http_headers': True,
            'dom': True,
            'cookies': True
        }
        self.init_scan_positions()
        
    def update_signal_safe(self, message):
        """Sanitize message before emitting signal"""
        sanitized_message = html.escape(str(message))
        self.update_signal.emit(sanitized_message)

    def init_scan_positions(self):
        """Initialize scan positions from resume data or defaults"""
        self.current_url_index = self.resume_data.get('url_index', 0)
        self.current_param_index = self.resume_data.get('param_index', 0)
        self.current_payload_index = self.resume_data.get('payload_index', 0)
        self.current_path_index = self.resume_data.get('path_index', 0)
        self.current_path_payload_index = self.resume_data.get('path_payload_index', 0)
        self.current_ext_payload_index = self.resume_data.get('ext_payload_index', 0)

    def stop(self):
        self.running = False

    def pause(self):
        self.paused = True
        self.update_signal.emit("Scan paused. You can resume later.")
        self.save_current_state()

    def save_current_state(self):
        """Save the current scan state"""
        state = {
            'url_index': self.current_url_index,
            'param_index': self.current_param_index,
            'payload_index': self.current_payload_index,
            'path_index': self.current_path_index,
            'path_payload_index': self.current_path_payload_index,
            'ext_payload_index': self.current_ext_payload_index,
            'target_urls': self.target_urls,
            'payloads': self.payloads,
            'use_headless': self.use_headless,
            'telegram_config': self.telegram_config,
            'test_config': self.test_config,
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.save_state_signal.emit(state)

    def resume(self):
        self.paused = False
        self.update_signal.emit("Resuming scan...")

    def setup_driver(self):
        """Initialize Chrome WebDriver (like in Code 1)"""
        try:
            chrome_options = Options()
            if self.use_headless:
                chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            # Use WebDriver Manager to handle driver compatibility
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(20)
            
            # Inject alert hook (simplified version)
            self.driver.execute_script("""
                window.original_alert = window.alert;
                window.alert = function(msg) { window.last_alert = msg; };
            """)
            
            self.update_signal.emit("Chrome driver initialized successfully!")
        except Exception as e:
            self.update_signal.emit(f"Error setting up Chrome driver: {str(e)}")
            results = {
                'query_xss': [], 'path_xss': [], 'extension_xss': [], 'dom_xss': [],
                'post_xss': [], 'header_xss': [], 'cookie_xss': [],
                'errors': [f"Failed to initialize Chrome driver: {str(e)}"]
            }
            self.result_signal.emit(results)
            raise

    def run(self):
        """Main scanning loop (sequential, like Code 1)"""
        results = {
            'query_xss': [], 'path_xss': [], 'extension_xss': [], 'dom_xss': [],
            'post_xss': [], 'header_xss': [], 'cookie_xss': [], 'errors': []
        }

        try:
            self.setup_driver()
            total_urls = len(self.target_urls)
            
            # Process URLs one by one (no ThreadPoolExecutor)
            for url_idx, target_url in enumerate(self.target_urls[self.current_url_index:], self.current_url_index):
                if not self.running:
                    break
                    
                self.current_url_index = url_idx
                # Emit the current URL index and total URLs
                self.url_index_signal.emit(url_idx + 1, total_urls)
                self.update_signal.emit(f"Starting scan on: {target_url}")
                parsed_url = urlparse(target_url)

                # Test Query Parameters (like Code 1)
                if parsed_url.query and self.test_config.get('query_params', True):
                    query_params = parse_qs(parsed_url.query)
                    param_keys = list(query_params.keys())
                    
                    for param_idx, param in enumerate(param_keys[self.current_param_index:], self.current_param_index):
                        if not self.running:
                            break
                            
                        self.current_param_index = param_idx
                        
                        for payload_idx, payload in enumerate(self.payloads[self.current_payload_index:], self.current_payload_index):
                            if not self.running:
                                break
                                
                            while self.paused:
                                self.msleep(500)
                                if not self.running:
                                    break
                                    
                            self.current_payload_index = payload_idx

                            malicious_params = query_params.copy()
                            malicious_params[param] = [payload]
                            malicious_query = urlencode(malicious_params, doseq=True)
                            malicious_url = urlunparse(parsed_url._replace(query=malicious_query))

                            self.update_signal.emit(f"Testing query param: {param} with payload: {payload}")
                            self.test_url(malicious_url, payload, 'query', param, results)
                            self.progress_signal.emit(1)
                            
                            if payload_idx % 5 == 0:
                                self.save_current_state()
                        
                        self.current_payload_index = 0
                    
                    self.current_param_index = 0

                # Test Path Segments (like Code 1)
                if self.test_config.get('path_segments', True):
                    path_parts = [p for p in parsed_url.path.split('/') if p]
                    
                    for path_idx, part in enumerate(path_parts[self.current_path_index:], self.current_path_index):
                        if not self.running:
                            break
                            
                        self.current_path_index = path_idx
                        
                        for payload_idx, payload in enumerate(self.payloads[self.current_path_payload_index:], self.current_path_payload_index):
                            if not self.running:
                                break
                                
                            while self.paused:
                                self.msleep(500)
                                if not self.running:
                                    break
                                    
                            self.current_path_payload_index = payload_idx

                            malicious_path = path_parts.copy()
                            malicious_path[path_idx] = payload
                            malicious_url = urlunparse(parsed_url._replace(path='/' + '/'.join(malicious_path)))

                            self.update_signal.emit(f"Testing path segment {path_idx} with payload: {payload}")
                            self.test_url(malicious_url, payload, 'path', path_idx, results)
                            self.progress_signal.emit(1)
                            
                            if payload_idx % 5 == 0:
                                self.save_current_state()
                        
                        self.current_path_payload_index = 0
                    
                    self.current_path_index = 0

                # Test File Extensions (like Code 1)
                if '.' in parsed_url.path and self.test_config.get('file_extensions', True):
                    for payload_idx, payload in enumerate(self.payloads[self.current_ext_payload_index:], self.current_ext_payload_index):
                        if not self.running:
                            break
                            
                        while self.paused:
                            self.msleep(500)
                            if not self.running:
                                break
                                
                        self.current_ext_payload_index = payload_idx

                        # Test before extension
                        malicious_path = parsed_url.path.replace('.', f"{payload}.")
                        malicious_url = urlunparse(parsed_url._replace(path=malicious_path))
                        self.update_signal.emit(f"Testing before extension with payload: {payload}")
                        self.test_url(malicious_url, payload, 'extension', 'before_extension', results)

                        # Test after extension
                        malicious_path = parsed_url.path + payload
                        malicious_url = urlunparse(parsed_url._replace(path=malicious_path))
                        self.update_signal.emit(f"Testing after extension with payload: {payload}")
                        self.test_url(malicious_url, payload, 'extension', 'after_extension', results)
                        self.progress_signal.emit(1)
                        
                        if payload_idx % 5 == 0:
                            self.save_current_state()
                    
                    self.current_ext_payload_index = 0

                # Test POST Parameters (simplified version)
                if self.test_config.get('post_params', True):
                    self.test_post_parameters(parsed_url, results)
                
                # Test HTTP Headers (simplified version)
                if self.test_config.get('http_headers', True):
                    self.test_http_headers(target_url, results)
                
                # Test DOM XSS
                if self.test_config.get('dom', True):
                    self.test_dom_xss(target_url, results)
                
                # Test Cookie-based XSS
                if self.test_config.get('cookies', True):
                    self.test_cookie_xss(target_url, results)

        except Exception as e:
            results['errors'].append(f"Scanner error: {str(e)}")
            self.update_signal.emit(f"Error during scan: {str(e)}")
        finally:
            if self.driver:
                self.driver.quit()
            self.result_signal.emit(results)

    def test_url(self, url, payload, vuln_type, location, results):
        """Test a URL for XSS (simplified alert detection like Code 1)"""
        try:
            self.update_signal_safe(f"Testing URL: {url}")
            
            # Reset alert detection
            self.driver.execute_script("window.last_alert = undefined;")
            
            # Navigate to URL
            self.driver.get(url)
            
            # Check if payload is reflected
            page_source = self.driver.page_source
            if payload in page_source:
                self.update_signal_safe("Payload found in page source!")
                
                # Check if an alert was triggered
                alert_triggered = self.driver.execute_script("return window.last_alert !== undefined;")
                if alert_triggered:
                    alert_text = self.driver.execute_script("return window.last_alert;")
                    # Sanitize alert text for display
                    sanitized_alert = html.escape(str(alert_text))
                    self.update_signal_safe(f"XSS Confirmed! Alert with text: {sanitized_alert}")
                    
                    # Record finding
                    result = {
                        'type': vuln_type,
                        'location': location,
                        'payload': payload,
                        'url': url,
                        'vulnerable': True,
                        'confirmed': True,
                        'status_code': 200,  # Can be enhanced with requests
                        'alert_text': alert_text
                    }
                    
                    results[f"{vuln_type}_xss"].append(result)
                    self.alert_count += 1
                    self.alert_count_signal.emit(self.alert_count)
                    
                    # Telegram notification
                    if self.telegram_config and self.telegram_config.get('enabled'):
                        self.telegram_signal.emit(url, f"{vuln_type.upper()} XSS in {location}")
                else:
                    self.update_signal_safe("Payload reflected but no alert triggered (potential reflected XSS)")
                    result = {
                        'type': vuln_type,
                        'location': location,
                        'payload': payload,
                        'url': url,
                        'vulnerable': True,
                        'confirmed': False,
                        'status_code': 200
                    }
                    results[f"{vuln_type}_xss"].append(result)
            else:
                self.update_signal_safe("Payload not found in page source - not vulnerable")

        except UnexpectedAlertPresentException:
            # Handle unexpected alerts (XSS confirmed)
            try:
                # Add a small delay to ensure the alert is fully loaded
                self.msleep(100)
                
                # Check if alert exists before trying to switch to it
                try:
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    self.update_signal_safe(f"XSS Confirmed via unexpected alert: {html.escape(str(alert_text))}")
                    
                    result = {
                        'type': vuln_type,
                        'location': location,
                        'payload': payload,
                        'url': url,
                        'vulnerable': True,
                        'confirmed': True,
                        'alert_text': alert_text
                    }
                    results[f"{vuln_type}_xss"].append(result)
                    self.alert_count += 1
                    self.alert_count_signal.emit(self.alert_count)
                    
                    if self.telegram_config and self.telegram_config.get('enabled'):
                        self.telegram_signal.emit(url, f"{vuln_type.upper()} XSS in {location}")
                except NoAlertPresentException:
                    # Alert was present but disappeared before we could access it
                    # Still consider this a successful XSS since it triggered an alert
                    self.update_signal_safe("XSS Confirmed! Alert was triggered but closed automatically")
                    
                    result = {
                        'type': vuln_type,
                        'location': location,
                        'payload': payload,
                        'url': url,
                        'vulnerable': True,
                        'confirmed': True,
                        'alert_text': "Alert was triggered but closed automatically"
                    }
                    results[f"{vuln_type}_xss"].append(result)
                    self.alert_count += 1
                    self.alert_count_signal.emit(self.alert_count)
                    
                    if self.telegram_config and self.telegram_config.get('enabled'):
                        self.telegram_signal.emit(url, f"{vuln_type.upper()} XSS in {location}")
            except Exception as e:
                self.update_signal_safe(f"Error handling alert: {str(e)}")
                results['errors'].append(f"Error handling alert for {url}: {str(e)}")

        except Exception as e:
            self.update_signal_safe(f"Error testing {url}: {str(e)}")
            results['errors'].append(f"Error testing {url}: {str(e)}")

    def test_post_parameters(self, parsed_url, results):
        """Test POST parameters (simplified version)"""
        if not parsed_url.query:
            return
            
        query_params = parse_qs(parsed_url.query)
        param_keys = list(query_params.keys())
        
        for param in param_keys:
            if not self.running:
                break
                
            for payload in self.payloads:
                if not self.running:
                    break
                    
                while self.paused:
                    self.msleep(500)
                    if not self.running:
                        break
                        
                self.update_signal_safe(f"Testing POST param: {param} with payload: {payload}")
                
                # Submit POST request via Selenium (simpler than temp files)
                try:
                    self.driver.get(parsed_url.geturl())
                    
                    # Properly escape payload for JavaScript
                    escaped_payload = payload.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"')
                    escaped_url = parsed_url.geturl().replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"')
                    
                    script = f"""
                        try {{
                            var form = document.createElement('form');
                            form.method = 'POST';
                            form.action = '{escaped_url}';
                            var input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = '{param}';
                            input.value = '{escaped_payload}';
                            form.appendChild(input);
                            document.body.appendChild(form);
                            form.submit();
                            return true;
                        }} catch(e) {{
                            console.error('Form submission error:', e);
                            return false;
                        }}
                    """
                    
                    # Execute with try-catch to handle JavaScript errors
                    submission_success = self.driver.execute_script(script)
                    
                    if not submission_success:
                        self.update_signal.emit(f"Failed to submit POST form for {param}")
                        continue
                    
                    # Wait for page to load after form submission
                    self.msleep(1000)
                    
                    # Check for XSS (same as test_url)
                    page_source = self.driver.page_source
                    if payload in page_source:
                        self.update_signal_safe("POST payload reflected!")
                        
                        # Check if an alert was triggered
                        try:
                            alert_triggered = self.driver.execute_script("return window.last_alert !== undefined;")
                            if alert_triggered:
                                alert_text = self.driver.execute_script("return window.last_alert;")
                                self.update_signal_safe(f"XSS Confirmed! Alert with text: {html.escape(str(alert_text))}")
                                
                                # Record finding and generate report
                                result = {
                                    'type': 'post',
                                    'location': param,
                                    'payload': payload,
                                    'url': parsed_url.geturl(),
                                    'vulnerable': True,
                                    'confirmed': True,
                                    'alert_text': alert_text,
                                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                }
                                results['post_xss'].append(result)
                                self.alert_count += 1
                                self.alert_count_signal.emit(self.alert_count)
                                
                                # Generate vulnerability report
                                if hasattr(self, 'tab_log_signal'):
                                    self.tab_log_signal.emit("Vulnerabilities", f"POST XSS found in {param} at {parsed_url.geturl()}")
                                
                                # Telegram notification if enabled
                                if self.telegram_config and self.telegram_config.get('enabled'):
                                    self.telegram_signal.emit(parsed_url.geturl(), f"POST XSS in {param}")
                        except Exception as js_error:
                            self.update_signal_safe(f"Error checking for alert: {str(js_error)}")
                except Exception as e:
                    self.update_signal_safe(f"Error testing POST: {str(e)}")
                    results['errors'].append(f"Error testing POST {param}: {str(e)}")

    def test_http_headers(self, target_url, results):
        """Test HTTP headers (simplified version)"""
        headers_to_test = ['Referer', 'User-Agent', 'X-Forwarded-For']
        
        for header in headers_to_test:
            if not self.running:
                break
                
            for payload in self.payloads:
                if not self.running:
                    break
                    
                while self.paused:
                    self.msleep(500)
                    if not self.running:
                        break
                        
                self.update_signal_safe(f"Testing header: {header} with payload: {payload}")
                
                try:
                    # Use requests to test header reflection
                    headers = {header: payload}
                    response = requests.get(target_url, headers=headers, timeout=10)
                    
                    if payload in response.text:
                        self.update_signal_safe(f"Header {header} reflected in response!")
                        result = {
                            'type': 'header',
                            'location': header,
                            'payload': payload,
                            'url': target_url,
                            'vulnerable': True,
                            'confirmed': False  # Can't confirm execution via requests
                        }
                        results['header_xss'].append(result)
                except Exception as e:
                    self.update_signal_safe(f"Error testing header {header}: {str(e)}")
                    results['errors'].append(f"Error testing header {header}: {str(e)}")

    def test_dom_xss(self, target_url, results):
        """Test for DOM-based XSS vulnerabilities"""
        if not self.running or not self.driver:
            return
            
        self.update_signal_safe(f"Testing DOM XSS on: {target_url}")
        
        try:
            # Navigate to the URL
            self.driver.get(target_url)
            
            # Wait for page to load
            self.msleep(1000)
            
            # Inject DOM XSS detection script
            detection_script = """
            (function() {
                // List of common DOM XSS sinks
                var sinks = [
                    'document.write', 'innerHTML', 'outerHTML', 'insertAdjacentHTML',
                    'eval', 'setTimeout', 'setInterval', 'location', 'document.cookie',
                    'document.domain', 'document.implementation.createHTMLDocument'
                ];
                
                // Check for sink usage with user input
                var vulnerableSinks = [];
                
                // Check URL parameters
                var urlParams = new URLSearchParams(window.location.search);
                var hasParams = false;
                
                for (let [key, value] of urlParams) {
                    hasParams = true;
                    // Check if parameter value is used in any sink
                    for (let sink of sinks) {
                        if (document.body && document.body.innerHTML.includes(sink) && 
                            document.body.innerHTML.includes(value)) {
                            vulnerableSinks.push({sink: sink, param: key});
                        }
                    }
                }
                
                // Check hash fragment
                if (window.location.hash) {
                    for (let sink of sinks) {
                        if (document.body && document.body.innerHTML.includes(sink) && 
                            document.body.innerHTML.includes(window.location.hash)) {
                            vulnerableSinks.push({sink: sink, param: 'hash'});
                        }
                    }
                }
                
                return {
                    vulnerableSinks: vulnerableSinks,
                    hasParams: hasParams,
                    url: window.location.href
                };
            })();
            """
            
            dom_results = self.driver.execute_script(detection_script)
            
            if dom_results.get('vulnerableSinks', []):
                for sink_info in dom_results['vulnerableSinks']:
                    self.update_signal_safe(f"Potential DOM XSS found! Sink: {sink_info['sink']}, Parameter: {sink_info['param']}")
                    
                    # Try to confirm with a test payload
                    parsed = urlparse(target_url)
                    query_params = parse_qs(parsed.query)
                    
                    for payload in self.payloads:
                        if sink_info['param'] != 'hash':
                            # Modify the parameter
                            if sink_info['param'] in query_params:
                                modified_params = query_params.copy()
                                modified_params[sink_info['param']] = [payload]
                                modified_query = urlencode(modified_params, doseq=True)
                                test_url = urlunparse(parsed._replace(query=modified_query))
                                
                                # Test the URL
                                self.update_signal_safe(f"Testing DOM XSS with payload in parameter {sink_info['param']}")
                                self.test_url(test_url, payload, 'dom', sink_info['sink'], results)
                                break
                        else:
                            # Test with hash payload
                            test_url = f"{target_url.split('#')[0]}#{payload}"
                            self.update_signal_safe("Testing DOM XSS with payload in hash fragment")
                            self.test_url(test_url, payload, 'dom', 'hash', results)
                            break
            elif dom_results.get('hasParams', False):
                self.update_signal_safe("No obvious DOM XSS sinks found with current parameters")
            else:
                self.update_signal_safe("No parameters to test for DOM XSS")
                
        except Exception as e:
            self.update_signal_safe(f"Error testing DOM XSS: {str(e)}")
            results['errors'].append(f"Error testing DOM XSS on {target_url}: {str(e)}")
    
    def test_cookie_xss(self, target_url, results):
        """Test for Cookie-based XSS vulnerabilities"""
        if not self.running or not self.driver:
            return
            
        self.update_signal_safe(f"Testing Cookie XSS on: {target_url}")
        
        try:
            # First navigate to the page to get any legitimate cookies
            self.driver.get(target_url)
            self.msleep(1000)
            
            # Get existing cookies
            original_cookies = self.driver.get_cookies()
            
            # Test each cookie with payloads
            for cookie in original_cookies:
                cookie_name = cookie['name']
                
                for payload in self.payloads:
                    if not self.running:
                        break
                        
                    while self.paused:
                        self.msleep(500)
                        if not self.running:
                            break
                    
                    # Delete the cookie first
                    self.driver.delete_cookie(cookie_name)
                    
                    # Add modified cookie with payload
                    self.driver.add_cookie({
                        'name': cookie_name,
                        'value': payload,
                        'path': cookie.get('path', '/'),
                        'domain': cookie.get('domain', None)
                    })
                    
                    # Refresh the page to trigger the cookie
                    self.driver.refresh()
                    self.msleep(1000)
                    
                    # Check if payload is reflected
                    page_source = self.driver.page_source
                    if payload in page_source:
                        self.update_signal_safe(f"Cookie {cookie_name} with payload reflected in response!")
                        
                        # Check if an alert was triggered
                        alert_triggered = self.driver.execute_script("return window.last_alert !== undefined;")
                        if alert_triggered:
                            alert_text = self.driver.execute_script("return window.last_alert;")
                            self.update_signal_safe(f"XSS Confirmed! Alert with text: {html.escape(str(alert_text))}")
                            
                            result = {
                                'type': 'cookie',
                                'location': cookie_name,
                                'payload': payload,
                                'url': target_url,
                                'vulnerable': True,
                                'confirmed': True,
                                'alert_text': alert_text
                            }
                            results['cookie_xss'].append(result)
                            self.alert_count += 1
                            self.alert_count_signal.emit(self.alert_count)
                            
                            if self.telegram_config and self.telegram_config.get('enabled'):
                                self.telegram_signal.emit(target_url, f"COOKIE XSS in {cookie_name}")
                        else:
                            result = {
                                'type': 'cookie',
                                'location': cookie_name,
                                'payload': payload,
                                'url': target_url,
                                'vulnerable': True,
                                'confirmed': False
                            }
                            results['cookie_xss'].append(result)
                    
                    # Restore original cookie
                    self.driver.delete_cookie(cookie_name)
                    self.driver.add_cookie(cookie)
            
        except Exception as e:
            self.update_signal_safe(f"Error testing Cookie XSS: {str(e)}")
            results['errors'].append(f"Error testing Cookie XSS on {target_url}: {str(e)}")

class XSSScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("XploitiX XSS Scanner")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 700)
        
        # Add window icon
        self.setWindowIcon(QIcon('icon.png'))
        self.scanner_thread = None
        self.scan_results = None
        self.current_scan_state = None
        self.default_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(2)>',
            'javascript:alert(3)',
            '"><script>alert(4)</script>',
            "'><svg/onload=alert(5)>",
            '%3Cscript%3Ealert(6)%3C/script%3E',
            '"><iframe src="javascript:alert(7)">'
        ]
        
        self.scan_start_time = None
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status_bar_time_and_memory)
        self.timer.start(1000)  # update every second
        self.init_ui()
        self.apply_dark_theme()
        # Footer label and timer for time/memory
        self.footer_label = QLabel()
        self.statusBar().addPermanentWidget(self.footer_label)
        self.footer_timer = QTimer(self)
        self.footer_timer.timeout.connect(self.update_footer)
        self.footer_timer.start(1000)  # Update every second
        self.update_footer()  # Initial update
        
    def create_test_config_group(self):
        """Create a group box with checkboxes for test configuration"""
        test_config_group = QGroupBox("Test Configuration")
        layout = QVBoxLayout()
        
        # Create checkboxes for each test type
        self.query_params_check = QCheckBox("Query Parameters")
        self.query_params_check.setChecked(True)
        
        self.path_segments_check = QCheckBox("Path Segments")
        self.path_segments_check.setChecked(True)
        
        self.file_extensions_check = QCheckBox("File Extensions")
        self.file_extensions_check.setChecked(True)
        
        self.post_params_check = QCheckBox("POST Parameters")
        self.post_params_check.setChecked(True)
        
        self.http_headers_check = QCheckBox("HTTP Headers")
        self.http_headers_check.setChecked(True)
        
        self.dom_check = QCheckBox("DOM XSS")
        self.dom_check.setChecked(True)
        
        self.cookies_check = QCheckBox("Cookie XSS")
        self.cookies_check.setChecked(True)
        
        # Add checkboxes to layout
        layout.addWidget(self.query_params_check)
        layout.addWidget(self.path_segments_check)
        layout.addWidget(self.file_extensions_check)
        layout.addWidget(self.post_params_check)
        layout.addWidget(self.http_headers_check)
        layout.addWidget(self.dom_check)
        layout.addWidget(self.cookies_check)
        
        # Add a "Select All" checkbox
        self.select_all_check = QCheckBox("Select All")
        self.select_all_check.setChecked(True)
        self.select_all_check.stateChanged.connect(self.toggle_all_tests)
        layout.addWidget(self.select_all_check)
        
        test_config_group.setLayout(layout)
        return test_config_group

    def toggle_all_tests(self, state):
        """Toggle all test checkboxes based on Select All state"""
        is_checked = state == Qt.Checked
        self.query_params_check.setChecked(is_checked)
        self.path_segments_check.setChecked(is_checked)
        self.file_extensions_check.setChecked(is_checked)
        self.post_params_check.setChecked(is_checked)
        self.http_headers_check.setChecked(is_checked)
        self.dom_check.setChecked(is_checked)
        self.cookies_check.setChecked(is_checked)

    def get_test_config(self):
        """Get the current test configuration from checkboxes"""
        return {
            'query_params': self.query_params_check.isChecked(),
            'path_segments': self.path_segments_check.isChecked(),
            'file_extensions': self.file_extensions_check.isChecked(),
            'post_params': self.post_params_check.isChecked(),
            'http_headers': self.http_headers_check.isChecked(),
            'dom': self.dom_check.isChecked(),
            'cookies': self.cookies_check.isChecked()
        }

    def update_footer(self):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        mem = psutil.virtual_memory().used // (1024 * 1024)
        self.footer_label.setText(f"Time: {now} | Memory: {mem} MB")
        
    def apply_dark_theme(self):
        """Apply dark theme to the application"""
        dark_stylesheet = """
        QWidget {
            background-color: #2D2D30;
            color: #CCCCCC;
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        
        QMainWindow {
            background-color: #1E1E1E;
        }
        
        QTabWidget::pane {
            border: 1px solid #3F3F46;
            background-color: #252526;
        }
        
        QTabBar::tab {
            background-color: #2D2D30;
            color: #CCCCCC;
            padding: 8px 12px;
            border: 1px solid #3F3F46;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        
        QTabBar::tab:selected {
            background-color: #007ACC;
            color: white;
        }
        
        QTabBar::tab:hover:!selected {
            background-color: #3E3E40;
        }
        
        QPushButton {
            background-color: #0E639C;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 3px;
        }
        
        QPushButton:hover {
            background-color: #1177BB;
        }
        
        QPushButton:pressed {
            background-color: #00548C;
        }
        
        QPushButton:disabled {
            background-color: #3F3F46;
            color: #999999;
        }
        
        QLineEdit, QTextEdit {
            background-color: #1E1E1E;
            color: #CCCCCC;
            border: 1px solid #3F3F46;
            padding: 4px;
            border-radius: 2px;
        }
        
        QProgressBar {
            border: 1px solid #3F3F46;
            border-radius: 2px;
            background-color: #1E1E1E;
            text-align: center;
            color: white;
        }
        
        QProgressBar::chunk {
            background-color: #007ACC;
        }
        
        QListWidget, QTreeWidget {
            background-color: #1E1E1E;
            color: #CCCCCC;
            border: 1px solid #3F3F46;
            border-radius: 2px;
        }
        
        QListWidget::item:selected, QTreeWidget::item:selected {
            background-color: #264F78;
            color: white;
        }
        
        QListWidget::item:hover, QTreeWidget::item:hover {
            background-color: #2D2D30;
        }
        
        QGroupBox {
            border: 1px solid #3F3F46;
            border-radius: 3px;
            margin-top: 1ex;
            padding-top: 10px;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 5px;
            color: #CCCCCC;
        }
        
        QCheckBox {
            color: #CCCCCC;
        }
        
        QCheckBox::indicator {
            width: 13px;
            height: 13px;
        }
        
        QCheckBox::indicator:unchecked {
            border: 1px solid #3F3F46;
            background-color: #1E1E1E;
        }
        
        QCheckBox::indicator:checked {
            border: 1px solid #007ACC;
            background-color: #007ACC;
        }
        
        QLabel {
            color: #CCCCCC;
        }
        
        QScrollBar:vertical {
            border: none;
            background-color: #2D2D30;
            width: 12px;
            margin: 12px 0 12px 0;
        }
        
        QScrollBar::handle:vertical {
            background-color: #3E3E42;
            min-height: 20px;
            border-radius: 6px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: #007ACC;
        }
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            border: none;
            background: none;
            height: 12px;
        }
        
        QScrollBar:horizontal {
            border: none;
            background-color: #2D2D30;
            height: 12px;
            margin: 0 12px 0 12px;
        }
        
        QScrollBar::handle:horizontal {
            background-color: #3E3E42;
            min-width: 20px;
            border-radius: 6px;
        }
        
        QScrollBar::handle:horizontal:hover {
            background-color: #007ACC;
        }
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            border: none;
            background: none;
            width: 12px;
        }
        """
        self.setStyleSheet(dark_stylesheet)

    def init_ui(self):
        """Initialize the main user interface"""
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        # Enhanced status bar
        self.statusBar().setStyleSheet("""
            QStatusBar {
                background-color: #252526;
                color: #CCCCCC;
                font-size: 12px;
                padding: 4px;
            }
            QStatusBar::item {
                border: none;
            }
        """)
        
        # Add status indicators
        self.scan_status = QLabel("Ready")
        self.memory_usage = QLabel("Memory: 0MB")
        self.scan_time = QLabel("Time: 00:00:00")
        
        self.statusBar().addPermanentWidget(self.scan_status)
        self.statusBar().addPermanentWidget(self.memory_usage)
        self.statusBar().addPermanentWidget(self.scan_time)
        
        self.init_url_input_section()
        self.init_payloads_section()
        self.init_telegram_section()
        self.init_options_section()
        self.init_control_buttons()
        self.init_results_tabs()
        self.init_progress_section()
        
        # Add alert count display
        self.alert_count_frame = QGroupBox("XSS Alerts")
        self.alert_count_layout = QHBoxLayout()
        self.alert_count_label = QLabel("Confirmed XSS: 0")
        self.alert_count_label.setStyleSheet("font-size: 16px; color: red;")
        self.alert_count_layout.addWidget(self.alert_count_label)
        self.alert_count_frame.setLayout(self.alert_count_layout)
        self.layout.addWidget(self.alert_count_frame)
        
    def init_url_input_section(self):
        """Initialize the URL input section"""
        url_layout = QVBoxLayout()
        url_group = QGroupBox("Target URLs")
        url_group_layout = QVBoxLayout()
        
        url_label = QLabel("Enter URLs (one per line):")
        self.url_input = QTextEdit()
        self.url_input.setPlaceholderText("https://example.com/path/file.php?param=value\nhttps://another-site.com/page?id=123")
        self.url_input.setMaximumHeight(100)
        
        url_buttons_layout = QHBoxLayout()
        load_urls_button = QPushButton("Load URLs from File")
        load_urls_button.clicked.connect(self.load_urls_from_file)
        url_buttons_layout.addWidget(load_urls_button)
        
        url_group_layout.addWidget(url_label)
        url_group_layout.addWidget(self.url_input)
        url_group_layout.addLayout(url_buttons_layout)
        url_group.setLayout(url_group_layout)
        url_layout.addWidget(url_group)
        self.layout.addLayout(url_layout)

    def init_payloads_section(self):
        """Initialize the payloads input section"""
        payloads_group = QGroupBox("XSS Payloads")
        payloads_layout = QVBoxLayout()
        
        payloads_label = QLabel("Enter payloads (one per line):")
        self.payloads_input = QTextEdit()
        self.payloads_input.setPlainText('\n'.join(self.default_payloads))
        
        payloads_buttons_layout = QHBoxLayout()
        load_payloads_button = QPushButton("Load Payloads from File")
        load_payloads_button.clicked.connect(self.load_payloads_from_file)
        reset_payloads_button = QPushButton("Reset to Default")
        reset_payloads_button.clicked.connect(self.reset_payloads)
        payloads_buttons_layout.addWidget(load_payloads_button)
        payloads_buttons_layout.addWidget(reset_payloads_button)
        
        payloads_layout.addWidget(payloads_label)
        payloads_layout.addWidget(self.payloads_input)
        payloads_layout.addLayout(payloads_buttons_layout)
        payloads_group.setLayout(payloads_layout)
        self.layout.addWidget(payloads_group)

    def init_telegram_section(self):
        """Initialize the Telegram notification section"""
        telegram_group = QGroupBox("Telegram Notifications")
        telegram_layout = QFormLayout()
        
        self.telegram_enabled = QCheckBox("Enable Telegram Notifications")
        self.telegram_token = QLineEdit()
        self.telegram_token.setPlaceholderText("Bot Token (e.g., 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ)")
        self.telegram_chat_id = QLineEdit()
        self.telegram_chat_id.setPlaceholderText("Chat ID (e.g., 123456789)")
        
        telegram_layout.addRow(self.telegram_enabled)
        telegram_layout.addRow("Bot Token:", self.telegram_token)
        telegram_layout.addRow("Chat ID:", self.telegram_chat_id)
        
        telegram_group.setLayout(telegram_layout)
        self.layout.addWidget(telegram_group)

    def init_options_section(self):
        """Initialize the options section"""
        options_layout = QHBoxLayout()
        options_left = QVBoxLayout()
        options_right = QVBoxLayout()
        
        # Headless mode checkbox
        self.headless_check = QCheckBox("Use Headless Chrome (recommended)")
        self.headless_check.setChecked(True)
        options_left.addWidget(self.headless_check)
        
        # Add test configuration group to right side
        test_config_group = self.create_test_config_group()
        options_right.addWidget(test_config_group)
        
        options_layout.addLayout(options_left)
        options_layout.addLayout(options_right)
        self.layout.addLayout(options_layout)

    def init_control_buttons(self):
        """Initialize the control buttons"""
        buttons_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        buttons_layout.addWidget(self.scan_button)
        
        self.pause_button = QPushButton("Pause Scan")
        self.pause_button.clicked.connect(self.pause_scan)
        self.pause_button.setEnabled(False)
        buttons_layout.addWidget(self.pause_button)
        
        self.resume_button = QPushButton("Resume Scan")
        self.resume_button.clicked.connect(self.resume_scan)
        self.resume_button.setEnabled(False)
        buttons_layout.addWidget(self.resume_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        buttons_layout.addWidget(self.clear_button)
        
        self.report_button = QPushButton("Generate HTML Report")
        self.report_button.clicked.connect(self.generate_html_report)
        self.report_button.setEnabled(False)
        buttons_layout.addWidget(self.report_button)
        
        self.save_state_button = QPushButton("Save Scan State")
        self.save_state_button.clicked.connect(self.save_scan_state)
        self.save_state_button.setEnabled(False)
        buttons_layout.addWidget(self.save_state_button)
        
        self.load_state_button = QPushButton("Load Scan State")
        self.load_state_button.clicked.connect(self.load_scan_state)
        buttons_layout.addWidget(self.load_state_button)
        
        self.about_button = QPushButton("About")
        self.about_button.clicked.connect(self.show_about)
        buttons_layout.addWidget(self.about_button)
        
        self.layout.addLayout(buttons_layout)

    def init_results_tabs(self):
        """Initialize the results tabs"""
        self.results_tabs = QTabWidget()
        self.layout.addWidget(self.results_tabs)
        
        # Initialize each results tab with a log area
        self.init_xss_tab("query", "Query XSS")
        self.init_xss_tab("path", "Path XSS")
        self.init_xss_tab("extension", "Extension XSS")
        self.init_xss_tab("dom", "DOM XSS")
        self.init_xss_tab("post", "POST XSS")
        self.init_xss_tab("header", "Header XSS")
        self.init_xss_tab("cookie", "Cookie XSS")
        self.init_errors_tab()
        self.init_visualization_tab()
        
    def init_xss_tab(self, tab_type, tab_name):
        """Initialize an XSS results tab with results list and log area"""
        tab = QWidget()
        layout = QVBoxLayout()
        tab.setLayout(layout)
        
        # Results list
        results_list = QListWidget()
        results_list.itemDoubleClicked.connect(self.copy_url_to_clipboard)
        setattr(self, f"{tab_type}_xss_list", results_list)
        
        # Log area
        log_area = QTextEdit()
        log_area.setReadOnly(True)
        log_area.setMaximumHeight(150)
        setattr(self, f"{tab_type}_xss_log", log_area)
        
        # Add widgets to tab
        layout.addWidget(QLabel(f"{tab_name} Results:"))
        layout.addWidget(results_list)
        layout.addWidget(log_area)
        
        self.results_tabs.addTab(tab, tab_name)

    def init_errors_tab(self):
        """Initialize the Errors tab"""
        self.errors_tab = QWidget()
        self.errors_layout = QVBoxLayout()
        self.errors_tab.setLayout(self.errors_layout)
        self.errors_list = QListWidget()
        self.errors_layout.addWidget(self.errors_list)
        self.results_tabs.addTab(self.errors_tab, "Errors")

    def init_visualization_tab(self):
        """Initialize the Visualization tab"""
        self.visualization_tab = QWidget()
        viz_layout = QVBoxLayout()
        self.visualization_tab.setLayout(viz_layout)
        
        # Create graphics view for visualization
        self.map_view = QGraphicsView()
        self.map_scene = QGraphicsScene()
        self.map_view.setScene(self.map_scene)
        self.map_view.setMinimumHeight(300)
        
        # Visualization controls
        controls_layout = QHBoxLayout()
        
        # Visualization type selector
        viz_type_group = QGroupBox("Visualization Type")
        viz_type_layout = QVBoxLayout()
        
        self.vuln_map_radio = QCheckBox("Vulnerability Map")
        self.vuln_map_radio.setChecked(True)
        self.vuln_map_radio.toggled.connect(self.update_visualization)
        
        self.payload_stats_radio = QCheckBox("Payload Effectiveness")
        self.payload_stats_radio.toggled.connect(self.update_visualization)
        
        self.waf_bypass_radio = QCheckBox("WAF Bypass Statistics")
        self.waf_bypass_radio.toggled.connect(self.update_visualization)
        
        viz_type_layout.addWidget(self.vuln_map_radio)
        viz_type_layout.addWidget(self.payload_stats_radio)
        viz_type_layout.addWidget(self.waf_bypass_radio)
        viz_type_group.setLayout(viz_type_layout)
        
        controls_layout.addWidget(viz_type_group)
        
        # Add control buttons
        self.refresh_viz_button = QPushButton("Refresh Visualization")
        self.refresh_viz_button.clicked.connect(self.update_visualization)
        controls_layout.addWidget(self.refresh_viz_button)
        
        self.export_viz_button = QPushButton("Export Visualization")
        self.export_viz_button.clicked.connect(self.export_visualization)
        controls_layout.addWidget(self.export_viz_button)
        
        # Add controls and visualization to layout
        viz_layout.addLayout(controls_layout)
        viz_layout.addWidget(self.map_view)
        
        # Add statistics area
        self.viz_stats_text = QTextEdit()
        self.viz_stats_text.setReadOnly(True)
        self.viz_stats_text.setMaximumHeight(150)
        viz_layout.addWidget(QLabel("Statistics:"))
        viz_layout.addWidget(self.viz_stats_text)
        
        self.results_tabs.addTab(self.visualization_tab, "Visualization")

    def init_progress_section(self):
        """Initialize the progress section"""
        progress_frame = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        # Status label
        self.status_label = QLabel("Status: Ready")
        progress_layout.addWidget(self.status_label)
        
        # URL counter label
        self.url_counter_label = QLabel("URL: 0/0")
        self.url_counter_label.setStyleSheet("font-weight: bold; color: #007ACC;")
        progress_layout.addWidget(self.url_counter_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3F3F46;
                border-radius: 4px;
                text-align: center;
                background-color: #1E1E1E;
                color: white;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #007ACC;
                border-radius: 4px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        progress_frame.setLayout(progress_layout)
        self.layout.addWidget(progress_frame)

    def load_urls_from_file(self):
        """Load URLs from a text file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load URLs from File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    self.url_input.setText('\n'.join(urls))
                QMessageBox.information(self, "Success", f"Loaded {len(urls)} URLs from file")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load URLs: {str(e)}")

    def load_payloads_from_file(self):
        """Load payloads from a text file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Payloads from File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                    self.payloads_input.setPlainText('\n'.join(payloads))
                QMessageBox.information(self, "Success", f"Loaded {len(payloads)} payloads from file")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load payloads: {str(e)}")

    def reset_payloads(self):
        """Reset payloads to default values"""
        self.payloads_input.setPlainText('\n'.join(self.default_payloads))

    def copy_url_to_clipboard(self, item):
        """Copy URL from list item to clipboard"""
        url = item.data(Qt.UserRole)
        clipboard = QApplication.clipboard()
        clipboard.setText(url)
        QMessageBox.information(self, "Copied", "URL copied to clipboard!")
        
        # Ask if user wants to open the URL in browser
        reply = QMessageBox.question(self, 'Open URL', 
                                     'Do you want to open this URL in your browser?',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            QDesktopServices.openUrl(QUrl(url))

    def connect_scanner_signals(self):
        """Connect all scanner thread signals to appropriate slots"""
        self.scanner_thread.result_signal.connect(self.update_results)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.telegram_signal.connect(self.send_telegram_notification)
        self.scanner_thread.save_state_signal.connect(self.auto_save_state)
        self.scanner_thread.finished.connect(self.scan_finished)
        self.scanner_thread.update_signal.connect(self.update_status)
        self.scanner_thread.alert_count_signal.connect(self.update_alert_count)
        self.scanner_thread.tab_log_signal.connect(self.add_tab_log)
        self.scanner_thread.url_index_signal.connect(self.update_url_counter)

    def start_scan(self):
        """Start the XSS scanning process"""
        urls_text = self.url_input.toPlainText().strip()
        if not urls_text:
            QMessageBox.warning(self, "Error", "Please enter at least one target URL")
            return
            
        target_urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
        
        payloads_text = self.payloads_input.toPlainText().strip()
        payloads = [p.strip() for p in payloads_text.split('\n') if p.strip()] if payloads_text else self.default_payloads
        
        if not payloads:
            QMessageBox.warning(self, "Error", "Please enter at least one XSS payload")
            return

        # Telegram configuration
        telegram_config = {
            'enabled': self.telegram_enabled.isChecked(),
            'token': self.telegram_token.text().strip(),
            'chat_id': self.telegram_chat_id.text().strip()
        }
        
        # Validate Telegram settings if enabled
        if telegram_config['enabled'] and (not telegram_config['token'] or not telegram_config['chat_id']):
            reply = QMessageBox.question(
                self, 'Telegram Configuration', 
                'Telegram notifications are enabled but token or chat ID is missing. Continue without notifications?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
            telegram_config['enabled'] = False

        self.clear_results()
        total_tests = self.calculate_total_tests(target_urls, payloads)
        self.progress_bar.setMaximum(total_tests)
        self.progress_bar.setValue(0)

        # Initialize scan results storage
        self.scan_results = self.initialize_results_structure()

        # Get test configuration
        test_config = self.get_test_config()

        self.scanner_thread = XSSScannerThread(
            target_urls=target_urls,
            payloads=payloads,
            use_headless=self.headless_check.isChecked(),
            telegram_config=telegram_config,
            resume_data=None,  # resume_data
            test_config=test_config
        )
        
        # Connect signals
        self.connect_scanner_signals()
        
        self.update_ui_for_scan_start()
        self.scanner_thread.start()
    
    def calculate_total_tests(self, target_urls, payloads):
        """Calculate the total number of tests to be performed for progress tracking"""
        total = 0
        
        for url in target_urls:
            parsed_url = urlparse(url)
            
            # Count query parameter tests
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                total += len(query_params) * len(payloads)
            
            # Count path segment tests
            path_parts = [p for p in parsed_url.path.split('/') if p]
            total += len(path_parts) * len(payloads)
            
            # Count extension tests (2 tests per payload if there's a file extension)
            if '.' in parsed_url.path:
                total += 2 * len(payloads)  # Before and after extension
                
            # Add DOM XSS tests (1 per URL)
            total += 1
        
        # Add a small buffer to ensure progress bar reaches 100%
        total = int(total * 1.05)  # Add 5% buffer
        
        return max(total, 1)  # Ensure at least 1 test to avoid division by zero
    
    def initialize_results_structure(self):
        """Initialize the results dictionary structure"""
        return {
            'query_xss': [],
            'path_xss': [],
            'extension_xss': [],
            'dom_xss': [],
            'post_xss': [],
            'header_xss': [],
            'cookie_xss': [],
            'errors': []
        }

    def add_tab_log(self, tab_name, message):
        """Add a log message to a specific tab"""
        # Find the tab by name
        for i in range(self.results_tabs.count()):
            if self.results_tabs.tabText(i) == tab_name:
                tab = self.results_tabs.widget(i)
                # Find the log area in the tab
                for child in tab.findChildren(QTextEdit):
                    child.append(message)
                    break
                break

    def update_ui_for_scan_start(self):
        """Update UI when scan starts"""
        self.scan_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_state_button.setEnabled(True)
        self.load_state_button.setEnabled(False)
        self.status_label.setText("Status: Scanning...")
        self.scan_start_time = datetime.datetime.now()
        
        # Create a timer to update the scan duration display
        if not hasattr(self, 'scan_timer'):
            self.scan_timer = QTimer(self)
            self.scan_timer.timeout.connect(self.update_scan_duration)
            
        self.scan_timer.start(1000)  # Update every second
        
        # Initialize the scan duration label if not already present
        if not hasattr(self, 'scan_duration_label'):
            self.scan_duration_label = QLabel("Duration: 00:00:00")
            self.statusBar().addPermanentWidget(self.scan_duration_label)
            
        # Initialize estimated time remaining label if not already present
        if not hasattr(self, 'estimated_time_label'):
            self.estimated_time_label = QLabel("Est. Remaining: --:--:--")
            self.statusBar().addPermanentWidget(self.estimated_time_label)
            
        # Initialize URL progress label if not already present
        if not hasattr(self, 'url_progress_label'):
            self.url_progress_label = QLabel("URL: 0/0")
            self.statusBar().addPermanentWidget(self.url_progress_label)

    def pause_scan(self):
        """Pause the current scan"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.pause()
            self.pause_button.setEnabled(False)
            self.resume_button.setEnabled(True)
            self.scan_button.setEnabled(False)
            self.save_state_button.setEnabled(True)
    
    def resume_scan(self):
        """Resume a paused scan"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.resume()
            self.pause_button.setEnabled(True)
            self.resume_button.setEnabled(False)
            self.scan_button.setEnabled(False)
            self.status_label.setText("Status: Scanning...")
            
            # Restore test configuration if available
            if hasattr(self, 'current_scan_state') and 'test_config' in self.current_scan_state:
                test_config = self.current_scan_state['test_config']
                self.query_params_check.setChecked(test_config.get('query_params', True))
                self.path_segments_check.setChecked(test_config.get('path_segments', True))
                self.file_extensions_check.setChecked(test_config.get('file_extensions', True))
                self.post_params_check.setChecked(test_config.get('post_params', True))
                self.http_headers_check.setChecked(test_config.get('http_headers', True))
                self.dom_check.setChecked(test_config.get('dom', True))
                self.cookies_check.setChecked(test_config.get('cookies', True))
    
    def auto_save_state(self, state):
        """Automatically save the current scan state"""
        self.current_scan_state = state
    
    def save_scan_state(self):
        """Save the current scan state to a file"""
        if not hasattr(self, 'current_scan_state'):
            QMessageBox.warning(self, "Error", "No scan state to save")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Scan State", 
            os.path.expanduser("~/xss_scan_state.json"),
            "JSON Files (*.json)"
        )
        
        if not file_path:
            return
            
        try:
            state_to_save = self.current_scan_state.copy()
            state_to_save['target_urls'] = [url.strip() for url in self.url_input.toPlainText().strip().split('\n') if url.strip()]
            state_to_save['payloads'] = [p.strip() for p in self.payloads_input.toPlainText().strip().split('\n') if p.strip()]
            state_to_save['use_headless'] = self.headless_check.isChecked()
            state_to_save['telegram_config'] = {
                'enabled': self.telegram_enabled.isChecked(),
                'token': self.telegram_token.text().strip(),
                'chat_id': self.telegram_chat_id.text().strip()
            }
            state_to_save['test_config'] = self.get_test_config()
            state_to_save['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            state_to_save['progress'] = self.progress_bar.value()
            state_to_save['max_progress'] = self.progress_bar.maximum()
            state_to_save['results'] = self.scan_results
            
            with open(file_path, 'w') as f:
                json.dump(state_to_save, f)
                
            QMessageBox.information(self, "Success", f"Scan state saved to {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save scan state: {str(e)}")
    
    def load_scan_state(self):
        """Load a saved scan state from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Scan State", 
            os.path.expanduser("~"),
            "JSON Files (*.json)"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'r') as f:
                state = json.load(f)
                
            # Validate the state file
            required_keys = ['url_index', 'param_index', 'payload_index', 'target_urls', 'payloads']
            if not all(key in state for key in required_keys):
                QMessageBox.warning(self, "Error", "Invalid scan state file")
                return
                
            # Restore UI state
            self.url_input.setPlainText('\n'.join(state['target_urls']))
            self.payloads_input.setPlainText('\n'.join(state['payloads']))
            self.headless_check.setChecked(state.get('use_headless', True))
            
            # Restore Telegram settings if available
            if 'telegram_config' in state:
                self.telegram_enabled.setChecked(state['telegram_config'].get('enabled', False))
                self.telegram_token.setText(state['telegram_config'].get('token', ''))
                self.telegram_chat_id.setText(state['telegram_config'].get('chat_id', ''))
            
            # Restore test configuration if available
            if 'test_config' in state:
                test_config = state['test_config']
                self.query_params_check.setChecked(test_config.get('query_params', True))
                self.path_segments_check.setChecked(test_config.get('path_segments', True))
                self.file_extensions_check.setChecked(test_config.get('file_extensions', True))
                self.post_params_check.setChecked(test_config.get('post_params', True))
                self.http_headers_check.setChecked(test_config.get('http_headers', True))
                self.dom_check.setChecked(test_config.get('dom', True))
                self.cookies_check.setChecked(test_config.get('cookies', True))
                
                # Update select all checkbox based on loaded state
                all_checked = all(test_config.values())
                self.select_all_check.setChecked(all_checked)
            
            # Restore results if available
            if 'results' in state:
                self.scan_results = state['results']
                self.update_results(state['results'])
                
            # Set progress bar
            if 'progress' in state and 'max_progress' in state:
                self.progress_bar.setMaximum(state['max_progress'])
                self.progress_bar.setValue(state['progress'])
            
            # Store the state for resuming
            self.current_scan_state = state
            
            # Enable resume button
            self.scan_button.setEnabled(False)
            self.resume_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self.save_state_button.setEnabled(True)
            
            timestamp = state.get('timestamp', 'unknown time')
            self.status_label.setText(f"Status: Loaded scan state from {timestamp}")
            
            QMessageBox.information(self, "Success", f"Scan state loaded from {file_path}")
            
            # Ask if user wants to resume the scan
            reply = QMessageBox.question(
                self, 'Resume Scan', 
                'Do you want to resume the scan now?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                self.resume_from_loaded_state()
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load scan state: {str(e)}")
    
    def resume_from_loaded_state(self):
        """Resume a scan from a loaded state"""
        if not hasattr(self, 'current_scan_state'):
            QMessageBox.warning(self, "Error", "No scan state to resume from")
            return
            
        # Get test configuration from state or use current UI settings
        test_config = self.current_scan_state.get('test_config', self.get_test_config())
        
        self.scanner_thread = XSSScannerThread(
            self.current_scan_state['target_urls'],
            self.current_scan_state['payloads'],
            self.headless_check.isChecked(),
            self.current_scan_state.get('telegram_config', {'enabled': False}),
            self.current_scan_state,
            test_config
        )
        
        self.connect_scanner_signals()
        self.update_ui_for_scan_start()
        self.scanner_thread.start()

    def stop_scan(self):
        """Stop the current scan"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.scanner_thread.wait()
            self.update_ui_for_scan_stop("Status: Scan stopped by user")

    def scan_finished(self):
        """Handle scan completion"""
        self.update_ui_for_scan_stop("Status: Scan completed")
        
        # Enable report button if we have results
        has_results = (
            self.query_xss_list.count() > 0 or
            self.path_xss_list.count() > 0 or
            self.extension_xss_list.count() > 0 or
            self.dom_xss_list.count() > 0
        )
        self.report_button.setEnabled(has_results)
        
        # Show completion popup with summary if we have scan results
        if self.scan_results:
            self.handle_scan_results(self.scan_results)
        else:
            QMessageBox.warning(self, "No Results", "No scan results were collected. Report generation will not be available.")

    def update_ui_for_scan_stop(self, status_message):
        """Update UI when scan stops"""
        self.scan_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.save_state_button.setEnabled(True)
        self.load_state_button.setEnabled(True)
        self.status_label.setText(status_message)
        self.url_counter_label.setText("URL: 0/0")  # Reset URL counter
        
        # Stop the scan timer if it exists
        if hasattr(self, 'scan_timer') and self.scan_timer.isActive():
            self.scan_timer.stop()
            
        # Calculate and store the final scan duration
        if self.scan_start_time:
            self.scan_end_time = datetime.datetime.now()
            self.scan_duration = self.scan_end_time - self.scan_start_time
            
            # Format duration as HH:MM:SS for display
            hours, remainder = divmod(self.scan_duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            duration_str = f"Duration: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
            
            # Update the duration label
            if hasattr(self, 'scan_duration_label'):
                self.scan_duration_label.setText(duration_str)
                
            # Reset estimated time remaining
            if hasattr(self, 'estimated_time_label'):
                self.estimated_time_label.setText("Est. Remaining: --:--:--")
                
        self.scan_start_time = None

    def update_status(self, message):
        """Update the status label with a message"""
        self.status_label.setText(f"Status: {message}")

    def update_progress(self, increment):
        """Update the progress bar"""
        self.progress_bar.setValue(self.progress_bar.value() + increment)

    def add_result_to_list(self, result, list_widget):
        """Add a scan result to the appropriate list widget"""
        result_text = f"""URL: {html.escape(str(result['url']))}
        Payload: {html.escape(str(result['payload']))}
        Type: {html.escape(str(result.get('type', 'UNKNOWN').upper()))} XSS in {html.escape(str(result.get('location', 'UNKNOWN')))}
        Status: {'Confirmed' if result.get('confirmed', False) else 'Potential'}
        Status Code: {html.escape(str(result.get('status_code', 'Unknown')))}
        Page Title: {html.escape(str(result.get('page_title', 'Unknown')))}
        WAF Protection: {html.escape(str(result.get('waf_protection', 'Unknown')))}"""
        
        item = QListWidgetItem(result_text)
        item.setData(Qt.UserRole, result['url'])
        list_widget.addItem(item)
        
    def update_results(self, results):
        """Update the results display with new scan results"""
        # Update stored results for report generation
        for key in results:
            if isinstance(results[key], list):
                if key not in self.scan_results:
                    self.scan_results[key] = []
                self.scan_results[key].extend(results[key])
        
        # Update each results tab
        if results['query_xss']:
            for vuln in results['query_xss']:
                self.add_result_to_list(vuln, self.query_xss_list)

        if results['path_xss']:
            for vuln in results['path_xss']:
                self.add_result_to_list(vuln, self.path_xss_list)

        if results['extension_xss']:
            for vuln in results['extension_xss']:
                self.add_result_to_list(vuln, self.extension_xss_list)

        if results['dom_xss']:
            for vuln in results['dom_xss']:
                self.add_result_to_list(vuln, self.dom_xss_list)
                
        if results.get('post_xss'):
            for vuln in results['post_xss']:
                self.add_result_to_list(vuln, self.post_xss_list)
                
        if results.get('header_xss'):
            for vuln in results['header_xss']:
                self.add_result_to_list(vuln, self.header_xss_list)
                
        if results.get('cookie_xss'):
            for vuln in results['cookie_xss']:
                self.add_result_to_list(vuln, self.cookie_xss_list)

        if results['errors']:
            for error in results['errors']:
                self.errors_list.addItem(error)
                
        # Update the visualization
        self.update_visualization()

    def clear_results(self):
        """Clear all scan results"""
        lists_to_clear = [
            'query_xss_list', 'path_xss_list', 'extension_xss_list',
            'dom_xss_list', 'post_xss_list', 'header_xss_list',
            'cookie_xss_list', 'errors_list'
        ]
        
        for list_name in lists_to_clear:
            if hasattr(self, list_name):
                getattr(self, list_name).clear()
        
        self.progress_bar.setValue(0)
        self.status_label.setText("Status: Ready")
        self.scan_results = None
        self.report_button.setEnabled(False)
        
        # Clear the visualization
        if hasattr(self, 'map_scene'):
            self.map_scene.clear()
        if hasattr(self, 'viz_stats_text'):
            self.viz_stats_text.clear()

    def send_telegram_notification(self, url, vuln_type):
        """Send a Telegram notification about a found vulnerability"""
        try:
            token = self.telegram_token.text().strip()
            chat_id = self.telegram_chat_id.text().strip()
            
            if not token or not chat_id:
                self.errors_list.addItem("Telegram notification failed: Missing token or chat ID")
                return
                
            message = f"🚨 XSS VULNERABILITY DETECTED 🚨\n\nType: {vuln_type}\nURL: {url}\n\nDetected by XploiiX XSS Scanner"
            
            api_url = f"https://api.telegram.org/bot{token}/sendMessage"
            response = requests.post(api_url, data={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            })
            
            if response.status_code == 200:
                self.status_label.setText(f"Status: Telegram notification sent")
            else:
                self.errors_list.addItem(f"Telegram notification failed: {response.text}")
        except Exception as e:
            self.errors_list.addItem(f"Telegram notification error: {str(e)}")

    def show_about(self):
        """Show the about dialog"""
        about_text = """
        <h2>XploitiX XSS Scanner</h2>
        <p>A powerful XSS vulnerability scanner with advanced detection capabilities.</p>
        <p>Features:</p>
        <ul>
            <li>Query parameter testing</li>
            <li>Path segment testing</li>
            <li>File extension testing</li>
            <li>DOM XSS detection</li>
            <li>Telegram notifications</li>
            <li>HTML report generation</li>
        </ul>
        <p>Version: 1.0</p>
        """
        QMessageBox.about(self, "About XploitiX", about_text)
        
    def generate_html_report(self):
        """Generate a professional HTML report with interactive features"""
        if not self.scan_results:
            QMessageBox.warning(self, "No Results", "No scan results available to generate a report.")
            return

        # Calculate report metrics
        confirmed_count = sum(len([v for v in self.scan_results[vuln_type] if v.get('confirmed', False)]) 
                            for vuln_type in ['query_xss', 'path_xss', 'extension_xss', 'dom_xss', 
                                            'post_xss', 'header_xss', 'cookie_xss'])
        
        waf_count = sum(1 for vuln_type in self.scan_results 
                    for v in self.scan_results[vuln_type] 
                    if isinstance(v, dict) and v.get('waf_protection', False))
        
        scan_duration = str(datetime.datetime.now() - self.scan_start_time).split('.')[0] if hasattr(self, 'scan_start_time') and self.scan_start_time else "N/A"

        # Vulnerability distribution data
        vuln_distribution = {
            'Query': len(self.scan_results.get('query_xss', [])),
            'Path': len(self.scan_results.get('path_xss', [])),
            'Extension': len(self.scan_results.get('extension_xss', [])),
            'DOM': len(self.scan_results.get('dom_xss', [])),
            'POST': len(self.scan_results.get('post_xss', [])),
            'Header': len(self.scan_results.get('header_xss', [])),
            'Cookie': len(self.scan_results.get('cookie_xss', []))
        }

        # Severity classification
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        for vuln_type in self.scan_results:
            for vuln in self.scan_results[vuln_type]:
                if isinstance(vuln, dict) and vuln.get('confirmed', False):
                    if 'script' in vuln.get('payload', '').lower():
                        severity_counts['High'] += 1
                    elif 'onerror' in vuln.get('payload', '').lower():
                        severity_counts['Medium'] += 1
                    else:
                        severity_counts['Low'] += 1

        default_filename = f"xss_scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save HTML Report", default_filename, "HTML Files (*.html)")
        
        if not file_path:
            return
            
        if not file_path.endswith('.html'):
            file_path += '.html'
            
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f'''<!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>XSS Scan Report</title>
                        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
                        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                        <style>
                            :root {{
                                --primary-color: #007ACC;
                                --secondary-color: #3F3F46;
                                --success-color: #4CAF50;
                                --danger-color: #D32F2F;
                                --warning-color: #FFC107;
                                --background-color: #1E1E1E;
                                --text-color: #E0E0E0;
                            }}

                            body {{
                                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                                line-height: 1.6;
                                margin: 0;
                                padding: 20px;
                                background-color: var(--background-color);
                                color: var(--text-color);
                            }}

                            .container {{
                                max-width: 1200px;
                                margin: 0 auto;
                            }}

                            .report-header {{
                                text-align: center;
                                padding: 2rem;
                                border-bottom: 2px solid var(--primary-color);
                                margin-bottom: 2rem;
                            }}

                            .summary-grid {{
                                display: grid;
                                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                                gap: 1.5rem;
                                margin-bottom: 2rem;
                            }}

                            .summary-card {{
                                background: #252526;
                                padding: 1.5rem;
                                border-radius: 8px;
                                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                                text-align: center;
                            }}

                            .chart-container {{
                                background: #252526;
                                padding: 1.5rem;
                                border-radius: 8px;
                                margin: 2rem 0;
                            }}

                            .finding {{
                                border: 1px solid #3A3A3A;
                                padding: 1.5rem;
                                margin: 1rem 0;
                                border-radius: 6px;
                                transition: transform 0.2s;
                            }}

                            .vulnerable {{
                                background-color: #2D2D30;
                                border-left: 4px solid var(--danger-color);
                            }}

                            .severity-badge {{
                                display: inline-block;
                                padding: 0.25rem 0.75rem;
                                border-radius: 20px;
                                font-size: 0.85rem;
                                font-weight: 600;
                                margin-bottom: 1rem;
                            }}

                            .high-severity {{ background: var(--danger-color); }}
                            .medium-severity {{ background: var(--warning-color); color: #000; }}
                            .low-severity {{ background: var(--secondary-color); }}

                            .details-table {{
                                width: 100%;
                                border-collapse: collapse;
                                margin: 1rem 0;
                            }}

                            .details-table td {{
                                padding: 0.75rem;
                                border-bottom: 1px solid #3A3A3A;
                                vertical-align: top;
                            }}

                            .remediation {{
                                background: #1B1B1B;
                                padding: 1rem;
                                border-radius: 4px;
                                margin-top: 1rem;
                            }}

                            @media print {{
                                .chart-container {{ page-break-inside: avoid; }}
                                .finding {{ border-left: none; }}
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <header class="report-header">
                                <h1 class="report-title">
                                    <i class="fas fa-shield-alt"></i>
                                    XSS Vulnerability Scan Report
                                </h1>
                                <p class="timestamp">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                            </header>

                            <section class="summary-grid">
                                <div class="summary-card">
                                    <h3><i class="fas fa-bug"></i> Total Vulnerabilities</h3>
                                    <p style="font-size: 2.5rem; color: var(--danger-color);">{confirmed_count}</p>
                                </div>
                                <div class="summary-card">
                                    <h3><i class="fas fa-clock"></i> Scan Duration</h3>
                                    <p style="font-size: 2.5rem; color: var(--primary-color);">{scan_duration}</p>
                                </div>
                                <div class="summary-card">
                                    <h3><i class="fas fa-lock"></i> WAF Protected</h3>
                                    <p style="font-size: 2.5rem; color: var(--success-color);">{waf_count}</p>
                                </div>
                            </section>

                            <section class="chart-container">
                                <h2><i class="fas fa-chart-pie"></i> Vulnerability Distribution</h2>
                                <canvas id="vulnDistributionChart"></canvas>
                            </section>

                            <section class="chart-container">
                                <h2><i class="fas fa-chart-bar"></i> Severity Breakdown</h2>
                                <canvas id="severityChart"></canvas>
                            </section>

                            <section class="findings">
                                <h2><i class="fas fa-exclamation-triangle"></i> Confirmed Findings</h2>''')

                # Vulnerability sections
                for vuln_type in ['query_xss', 'path_xss', 'extension_xss', 'dom_xss', 
                                'post_xss', 'header_xss', 'cookie_xss']:
                    if self.scan_results.get(vuln_type):
                        confirmed_vulns = [v for v in self.scan_results[vuln_type] if isinstance(v, dict) and v.get('confirmed', False)]
                        if confirmed_vulns:
                            f.write(f'''
                            <h3>{vuln_type.replace("_", " ").title()} ({len(confirmed_vulns)})</h3>''')
                            
                            for idx, vuln in enumerate(confirmed_vulns, 1):
                                # Determine severity
                                severity = 'High'
                                if 'onerror' in vuln.get('payload', '').lower():
                                    severity = 'Medium'
                                elif not ('script' in vuln.get('payload', '').lower()):
                                    severity = 'Low'
                                    
                                f.write(f'''
                                <div class="finding vulnerable">
                                    <div class="severity-badge {severity.lower()}-severity">{severity.upper()}</div>
                                    <h4>Finding #{idx}</h4>
                                    <table class="details-table">
                                    <tr><td>URL</td><td class="url">{html.escape(str(vuln.get('url', 'N/A')))}</td></tr>
                                    <tr><td>Payload</td><td><code class="payload">{html.escape(str(vuln.get('payload', 'N/A')))}</code></td></tr>
                                    <tr><td>Location</td><td>{html.escape(str(vuln.get('location', 'N/A')))}</td></tr>
                                    <tr><td>Parameter</td><td>{html.escape(str(vuln.get('parameter', 'N/A')))}</td></tr>
                                    <tr><td>Status Code</td><td>{html.escape(str(vuln.get('status_code', 'N/A')))}</td></tr>
                                    <tr><td>WAF Protection</td><td>{html.escape(str(vuln.get('waf_protection', 'None detected')))}</td></tr>
                                    <tr><td>Response</td><td><pre class="response">{html.escape(str(vuln.get('response', 'N/A')))}</pre></td></tr>
                                    </table>
                                    <div class="remediation">
                                        <h5>Recommended Remediation:</h5>
                                        {self.get_remediation_advice(vuln_type) if hasattr(self, 'get_remediation_advice') else self.default_remediation_advice(vuln_type)}
                                    </div>
                                </div>''')

                # Error section
                if self.scan_results.get('errors'):
                    f.write('''
                    <section class="chart-container">
                        <h2><i class="fas fa-exclamation-circle"></i> Scan Errors</h2>
                        <ul>''')
                    for error in self.scan_results['errors']:
                        f.write(f'<li>{html.escape(str(error))}</li>')
                    f.write('</ul></section>')

                # Charts initialization
                f.write(f'''
                            </section>

                            <script>
                                // Vulnerability Distribution Chart
                                new Chart(document.getElementById('vulnDistributionChart'), {{
                                    type: 'doughnut',
                                    data: {{
                                        labels: {list(vuln_distribution.keys())},
                                        datasets: [{{
                                            data: {list(vuln_distribution.values())},
                                            backgroundColor: [
                                                '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                                                '#9966FF', '#FF9F40', '#8AC249'
                                            ]
                                        }}]
                                    }},
                                    options: {{
                                        responsive: true,
                                        plugins: {{
                                            legend: {{ position: 'bottom' }},
                                            title: {{ display: true, text: 'Vulnerability Type Distribution' }}
                                        }}
                                    }}
                                }});

                                // Severity Breakdown Chart
                                new Chart(document.getElementById('severityChart'), {{
                                    type: 'bar',
                                    data: {{
                                        labels: {list(severity_counts.keys())},
                                        datasets: [{{
                                            label: 'Vulnerability Severity',
                                            data: {list(severity_counts.values())},
                                            backgroundColor: [
                                                'rgba(255, 99, 132, 0.7)',
                                                'rgba(255, 206, 86, 0.7)',
                                                'rgba(75, 192, 192, 0.7)'
                                            ]
                                        }}]
                                    }},
                                    options: {{
                                        responsive: true,
                                        scales: {{
                                            y: {{ beginAtZero: true }}
                                        }},
                                        plugins: {{
                                            title: {{ display: true, text: 'Vulnerability Severity Distribution' }}
                                        }}
                                    }}
                                }});
                            </script>

                            <footer>
                                <p>Generated by XSS Scanner</p>
                                <p>© {datetime.datetime.now().year} All rights reserved.</p>
                            </footer>
                        </div>
                    </body>
                    </html>''')

                QMessageBox.information(self, "Report Generated", f"HTML report saved to {file_path}")
                
                reply = QMessageBox.question(self, 'Open Report', 
                                            'Do you want to open the report now?',
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                
                if reply == QMessageBox.Yes:
                    QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate report: {str(e)}")
            
    def default_remediation_advice(self, vuln_type):
        """Provide default remediation advice if get_remediation_advice is not available"""
        advice = {
            'query_xss': "Sanitize and validate all query parameters. Use context-appropriate encoding and consider implementing a Content Security Policy.",
            'path_xss': "Validate URL path segments and avoid directly reflecting user-controlled path components in the response.",
            'extension_xss': "Validate file extensions and avoid directly reflecting user input in the response.",
            'dom_xss': "Use safe DOM APIs and avoid using innerHTML, document.write, or eval with user-controlled input.",
            'post_xss': "Sanitize and validate all POST parameters. Use context-appropriate encoding.",
            'header_xss': "Validate and sanitize all HTTP headers that might be reflected in the response.",
            'cookie_xss': "Validate cookie values and avoid reflecting them in the response. Set the HttpOnly flag on sensitive cookies."
        }
        return advice.get(vuln_type, "Implement proper input validation, output encoding, and consider using a Content Security Policy.")

    def handle_scan_results(self, results):
        """Handle the scan results after completion"""
        self.scan_results = results
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.status_label.setText("Scan completed!")
        
        # Enable buttons
        self.scan_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        
        # Process results
        total_confirmed = 0
        total_potential = 0
        processed_urls = set()
        
        for vuln_type in ['query_xss', 'path_xss', 'extension_xss', 'dom_xss', 'post_xss', 'header_xss', 'cookie_xss']:
            if vuln_type in results:
                for result in results[vuln_type]:
                    result_id = f"{result['url']}|{result['payload']}|{result['location']}"
                    
                    if result_id in processed_urls:
                        continue
                    
                    processed_urls.add(result_id)
                    
                    if result.get('vulnerable', False):
                        if result.get('confirmed', False):
                            total_confirmed += 1
                        else:
                            total_potential += 1
        
        # Show completion popup with summary
        self.show_scan_completion_popup(total_confirmed, total_potential)
    
    def show_scan_completion_popup(self, confirmed_count, potential_count):
        """Show a popup with scan completion summary"""
        msg_box = QMessageBox()
        msg_box.setWindowTitle("XploitiX Scan Complete")
        
        # Set icon based on results
        if confirmed_count > 0:
            msg_box.setIcon(QMessageBox.Critical)
        elif potential_count > 0:
            msg_box.setIcon(QMessageBox.Warning)
        else:
            msg_box.setIcon(QMessageBox.Information)
        
        # Create message
        message = f"<h3>Scan Completed Successfully</h3>"
        
        # Add scan duration if available
        if hasattr(self, 'scan_duration'):
            hours, remainder = divmod(self.scan_duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            duration_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
            message += f"<p><b>Scan Duration:</b> {duration_str}</p>"
        
        message += f"<p><b>Confirmed XSS Vulnerabilities:</b> {confirmed_count}</p>"
        message += f"<p><b>Potential XSS Vulnerabilities:</b> {potential_count}</p>"
        
        if confirmed_count > 0:
            message += "<p style='color: #FF5555;'><b>Warning:</b> Critical vulnerabilities were found!</p>"
            message += "<p>Check the results tabs for details.</p>"
        elif potential_count > 0:
            message += "<p style='color: #FFAA55;'><b>Note:</b> Potential vulnerabilities were found.</p>"
            message += "<p>Check the results tabs for details.</p>"
        else:
            message += "<p style='color: #55AA55;'><b>Good news!</b> No vulnerabilities were found.</p>"
        
        msg_box.setText(message)
        
        # Add buttons
        if confirmed_count > 0:
            msg_box.addButton("Generate Report", QMessageBox.AcceptRole)
            msg_box.addButton("Close", QMessageBox.RejectRole)
            
            # Connect the clicked signal
            msg_box.buttonClicked.connect(lambda button: 
                self.generate_html_report() if button.text() == "Generate Report" else None)
        else:
            msg_box.addButton("Close", QMessageBox.AcceptRole)
        
        # Apply dark theme to the message box
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #2D2D30;
                color: #CCCCCC;
            }
            QLabel {
                color: #CCCCCC;
            }
            QPushButton {
                background-color: #0E639C;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #1177BB;
            }
        """)
        
        # Show the message box
        msg_box.exec_()

    def update_visualization(self):
        """Update the visualization based on current scan results"""
        self.map_scene.clear()
        self.viz_stats_text.clear()
        
        if not hasattr(self, 'scan_results') or not self.scan_results:
            self.map_scene.addText("No scan results available. Run a scan first.")
            return
        
        if self.vuln_map_radio.isChecked():
            self.show_vulnerability_map()
        elif self.payload_stats_radio.isChecked():
            self.show_payload_effectiveness()
        elif self.waf_bypass_radio.isChecked():
            self.show_waf_bypass_stats()

    def show_vulnerability_map(self):
        """Display a visual map of vulnerable points"""
        domains = {}
        
        for vuln_type in ['query_xss', 'path_xss', 'extension_xss', 'dom_xss', 'post_xss', 'header_xss', 'cookie_xss']:
            if vuln_type in self.scan_results:
                for result in self.scan_results[vuln_type]:
                    if not result.get('vulnerable', False):
                        continue
                        
                    url = result.get('url', '')
                    try:
                        parsed = urlparse(url)
                        domain = parsed.netloc
                        
                        if domain not in domains:
                            domains[domain] = {
                                'confirmed': 0,
                                'potential': 0,
                                'paths': set(),
                                'vulnerabilities': []
                            }
                        
                        domains[domain]['paths'].add(parsed.path)
                        domains[domain]['vulnerabilities'].append(result)
                        
                        if result.get('confirmed', False):
                            domains[domain]['confirmed'] += 1
                        else:
                            domains[domain]['potential'] += 1
                    except:
                        continue
        
        if not domains:
            self.map_scene.addText("No vulnerabilities found to visualize.")
            return
        
        y_pos = 10
        
        for domain, data in domains.items():
            domain_text = self.map_scene.addText(f"{domain} ({data['confirmed']} confirmed, {data['potential']} potential)")
            domain_text.setPos(10, y_pos)
            domain_text.setFont(QFont("Arial", 12, QFont.Bold))
            y_pos += 30
            
            for path in sorted(data['paths']):
                path_confirmed = sum(1 for v in data['vulnerabilities'] if urlparse(v['url']).path == path and v.get('confirmed', False))
                path_potential = sum(1 for v in data['vulnerabilities'] if urlparse(v['url']).path == path and not v.get('confirmed', False) and v.get('vulnerable', False))
                
                path_rect = QGraphicsRectItem(10, y_pos, 600, 25)
                
                if path_confirmed > 0:
                    path_rect.setBrush(QBrush(QColor(200, 50, 50, 100)))
                elif path_potential > 0:
                    path_rect.setBrush(QBrush(QColor(200, 150, 50, 100)))
                else:
                    path_rect.setBrush(QBrush(QColor(50, 50, 50, 100)))
                    
                self.map_scene.addItem(path_rect)
                
                path_text = self.map_scene.addText(f"{path} ({path_confirmed} confirmed, {path_potential} potential)")
                path_text.setPos(15, y_pos + 3)
                
                y_pos += 30
            
            y_pos += 20
        
        self.map_scene.setSceneRect(0, 0, 650, y_pos)
        
        stats = f"Total Domains: {len(domains)}\n"
        stats += f"Total Confirmed Vulnerabilities: {sum(d['confirmed'] for d in domains.values())}\n"
        stats += f"Total Potential Vulnerabilities: {sum(d['potential'] for d in domains.values())}\n"
        self.viz_stats_text.setText(stats)

    def show_payload_effectiveness(self):
        """Display statistics about payload effectiveness"""
        payload_stats = {}
        
        for vuln_type in ['query_xss', 'path_xss', 'extension_xss', 'dom_xss', 'post_xss', 'header_xss', 'cookie_xss']:
            if vuln_type in self.scan_results:
                for result in self.scan_results[vuln_type]:
                    if not result.get('vulnerable', False):
                        continue
                        
                    payload = result.get('payload', '')
                    
                    if payload not in payload_stats:
                        payload_stats[payload] = {
                            'confirmed': 0,
                            'potential': 0,
                            'total': 0
                        }
                    
                    payload_stats[payload]['total'] += 1
                    
                    if result.get('confirmed', False):
                        payload_stats[payload]['confirmed'] += 1
                    else:
                        payload_stats[payload]['potential'] += 1
        
        if not payload_stats:
            self.map_scene.addText("No payload statistics available.")
            return
        
        sorted_payloads = sorted(payload_stats.items(), key=lambda x: x[1]['confirmed'], reverse=True)
        
        y_pos = 10
        
        header_text = self.map_scene.addText("Payload Effectiveness (sorted by confirmed vulnerabilities)")
        header_text.setPos(10, y_pos)
        header_text.setFont(QFont("Arial", 12, QFont.Bold))
        y_pos += 30
        
        for payload, stats in sorted_payloads:
            bar_width = stats['confirmed'] * 20
            if bar_width < 5:
                bar_width = 5
            
            bar_rect = QGraphicsRectItem(10, y_pos, bar_width, 20)
            bar_rect.setBrush(QBrush(QColor(200, 50, 50)))
            self.map_scene.addItem(bar_rect)
            
            pot_bar_width = stats['potential'] * 10
            if pot_bar_width > 0:
                pot_bar_rect = QGraphicsRectItem(10 + bar_width, y_pos, pot_bar_width, 20)
                pot_bar_rect.setBrush(QBrush(QColor(200, 150, 50)))
                self.map_scene.addItem(pot_bar_rect)
            
            payload_text = self.map_scene.addText(f"{payload} ({stats['confirmed']} confirmed, {stats['potential']} potential)")
            payload_text.setPos(15 + bar_width + pot_bar_width, y_pos)
            
            y_pos += 25
        
        self.map_scene.setSceneRect(0, 0, 650, y_pos)
        
        stats = f"Total Unique Payloads: {len(payload_stats)}\n"
        stats += f"Most Effective Payload: {sorted_payloads[0][0]} ({sorted_payloads[0][1]['confirmed']} confirmed)\n"
        stats += f"Total Confirmed Vulnerabilities: {sum(s['confirmed'] for s in payload_stats.values())}\n"
        self.viz_stats_text.setText(stats)

    def show_waf_bypass_stats(self):
        """Display statistics about WAF bypass effectiveness"""
        waf_stats = {
            'No': {'confirmed': 0, 'potential': 0, 'total': 0},
            'Yes (Cloudflare)': {'confirmed': 0, 'potential': 0, 'total': 0},
            'Yes (Akamai)': {'confirmed': 0, 'potential': 0, 'total': 0},
            'Yes (Incapsula)': {'confirmed': 0, 'potential': 0, 'total': 0},
            'Yes (F5 BIG-IP)': {'confirmed': 0, 'potential': 0, 'total': 0},
            'Unknown': {'confirmed': 0, 'potential': 0, 'total': 0}
        }

        waf_bypass_payloads = {waf: {} for waf in waf_stats.keys()}
        
        for vuln_type in ['query_xss', 'path_xss', 'extension_xss', 'dom_xss', 'post_xss', 'header_xss', 'cookie_xss']:
            if vuln_type in self.scan_results:
                for result in self.scan_results[vuln_type]:
                    if not result.get('vulnerable', False):
                        continue
                        
                    waf = result.get('waf_protection', 'Unknown')
                    payload = result.get('payload', '')
                    
                    waf_stats[waf]['total'] += 1
                    
                    if result.get('confirmed', False):
                        waf_stats[waf]['confirmed'] += 1
                        
                        if payload not in waf_bypass_payloads[waf]:
                            waf_bypass_payloads[waf][payload] = 0
                        waf_bypass_payloads[waf][payload] += 1
                    else:
                        waf_stats[waf]['potential'] += 1
        
        y_pos = 10
        
        header_text = self.map_scene.addText("WAF Bypass Statistics")
        header_text.setPos(10, y_pos)
        header_text.setFont(QFont("Arial", 12, QFont.Bold))
        y_pos += 30
        
        for waf, stats in waf_stats.items():
            if stats['total'] == 0:
                continue
                
            bar_width = stats['confirmed'] * 20
            if bar_width < 5 and stats['confirmed'] > 0:
                bar_width = 5
            
            if bar_width > 0:
                bar_rect = QGraphicsRectItem(10, y_pos, bar_width, 20)
                bar_rect.setBrush(QBrush(QColor(200, 50, 50)))
                self.map_scene.addItem(bar_rect)
            
            waf_text = self.map_scene.addText(f"{waf} ({stats['confirmed']} confirmed, {stats['potential']} potential)")
            waf_text.setPos(15 + bar_width, y_pos)
            
            y_pos += 25
            
            if waf_bypass_payloads[waf]:
                top_payloads = sorted(waf_bypass_payloads[waf].items(), key=lambda x: x[1], reverse=True)[:3]
                
                for payload, count in top_payloads:
                    payload_text = self.map_scene.addText(f"  → {payload} ({count} times)")
                    payload_text.setPos(30, y_pos)
                    y_pos += 20
                
                y_pos += 5
        
        self.map_scene.setSceneRect(0, 0, 650, y_pos)
        
        total_confirmed = sum(s['confirmed'] for s in waf_stats.values())
        total_potential = sum(s['potential'] for s in waf_stats.values())
        
        stats = f"Total WAF Bypass Attempts: {total_confirmed + total_potential}\n"
        stats += f"Successful WAF Bypasses: {total_confirmed}\n"
        
        most_bypassed = max(waf_stats.items(), key=lambda x: x[1]['confirmed'] if x[0] != 'No' and x[0] != 'Unknown' else -1)
        if most_bypassed[1]['confirmed'] > 0 and most_bypassed[0] not in ['No', 'Unknown']:
            stats += f"Most Bypassed WAF: {most_bypassed[0]} ({most_bypassed[1]['confirmed']} times)\n"
        
        self.viz_stats_text.setText(stats)
        
    def export_visualization(self):
        """Export the current visualization as an image"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Visualization", 
                                                 f"xploitix_visualization_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png", 
                                                 "PNG Files (*.png)")
        
        if not file_path:
            return
            
        if not file_path.endswith('.png'):
            file_path += '.png'
        
        image = QImage(self.map_scene.sceneRect().size().toSize(), QImage.Format_ARGB32)
        image.fill(Qt.transparent)
        
        painter = QPainter(image)
        self.map_scene.render(painter)
        painter.end()
        
        if image.save(file_path):
            QMessageBox.information(self, "Export Successful", f"Visualization saved to {file_path}")
        else:
            QMessageBox.critical(self, "Export Failed", "Failed to save visualization image")

    def update_scan_duration(self):
        """Update the scan duration display"""
        if self.scan_start_time:
            current_time = datetime.datetime.now()
            duration = current_time - self.scan_start_time
            
            # Format duration as HH:MM:SS
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            duration_str = f"Duration: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
            
            # Update the duration label
            if hasattr(self, 'scan_duration_label'):
                self.scan_duration_label.setText(duration_str)
                
            # Calculate and update estimated time remaining
            if hasattr(self, 'progress_bar') and hasattr(self, 'estimated_time_label'):
                progress_value = self.progress_bar.value()
                progress_max = self.progress_bar.maximum()
                
                if progress_value > 0 and progress_value < progress_max:
                    # Calculate estimated time based on progress
                    progress_ratio = progress_value / progress_max
                    elapsed_seconds = duration.total_seconds()
                    
                    # Estimate total time and remaining time
                    if progress_ratio > 0:
                        total_estimated_seconds = elapsed_seconds / progress_ratio
                        remaining_seconds = total_estimated_seconds - elapsed_seconds
                        
                        # Format remaining time
                        hours, remainder = divmod(remaining_seconds, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        remaining_str = f"Est. Remaining: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
                        
                        self.estimated_time_label.setText(remaining_str)
                    else:
                        self.estimated_time_label.setText("Est. Remaining: --:--:--")
                else:
                    self.estimated_time_label.setText("Est. Remaining: --:--:--")
                    
    def update_status_bar_time_and_memory(self):
        """Update the status bar with current time and memory usage"""
        # Update memory usage
        process = psutil.Process()
        mem_mb = process.memory_info().rss / 1024 / 1024
        self.memory_usage.setText(f"Memory: {mem_mb:.1f}MB")
        
        # Update scan time
        if self.scan_start_time:
            elapsed = datetime.datetime.now() - self.scan_start_time
            hours, remainder = divmod(elapsed.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.scan_time.setText(f"Time: {hours:02d}:{minutes:02d}:{seconds:02d}")
        else:
            self.scan_time.setText("Time: 00:00:00")
            
    def update_alert_count(self, count):
        """Update the alert count label"""
        self.alert_count_label.setText(f"Confirmed XSS: {count}")
        
    def update_url_progress(self, current, total):
        """Update the URL progress label"""
        if hasattr(self, 'url_progress_label'):
            self.url_progress_label.setText(f"URL: {current}/{total}")
            
    def update_url_counter(self, current_index, total_urls):
        """Update the URL counter display"""
        self.url_counter_label.setText(f"URL: {current_index}/{total_urls}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = XSSScannerGUI()
    scanner.show()
    sys.exit(app.exec())