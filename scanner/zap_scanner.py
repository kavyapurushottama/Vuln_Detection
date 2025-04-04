from zapv2 import ZAPv2
import time
import os
import subprocess
from urllib.parse import urlparse
from typing import Optional, Dict, Any

def validate_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def start_zap_daemon() -> bool:
    try:
        # Kill any existing ZAP processes
        try:
            subprocess.run(['taskkill', '/F', '/IM', 'java.exe'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE)
            time.sleep(2)  # Wait for process to fully terminate
        except:
            pass

        zap_dir = r"C:\Program Files\ZAP\Zed Attack Proxy"
        zap_jar = os.path.join(zap_dir, "zap-2.16.0.jar")
        
        if os.path.exists(zap_jar):
            print(f"Found ZAP at: {zap_jar}")
            print("Starting ZAP daemon...")
            
            # Change working directory to ZAP directory
            original_dir = os.getcwd()
            os.chdir(zap_dir)
            
            # Use a different home directory
            # Fix the TEMP path handling
            temp_dir = os.getenv('TEMP')
            if temp_dir is None:
                temp_dir = os.path.join(os.path.expanduser('~'), 'temp')
            zap_home = os.path.join(temp_dir, 'ZAP_temp')
            os.makedirs(zap_home, exist_ok=True)
            
            process = subprocess.Popen(
                ['java', '-jar', zap_jar, 
                 '-daemon',
                 '-dir', zap_home,
                 '-config', 'api.disablekey=true',
                 '-config', 'scanner.alertThreshold=MEDIUM',
                 '-config', 'api.addrs.addr.name=.*',  # Allow API access from anywhere
                 '-config', 'api.addrs.addr.regex=true',
                 '-config', 'scanner.maxAlertsPerRule=10',  # Limit alerts per rule
                 '-silent',
                 '-port', '8080'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Restore original directory
            os.chdir(original_dir)
            
            # Check for immediate failure
            time.sleep(2)
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                print(f"ZAP failed to start. Output:\n{stdout}\nErrors:\n{stderr}")
                return False
            
            print("ZAP process started, waiting for initialization...")
            time.sleep(15)
            
            if process.poll() is not None:
                print("ZAP process terminated unexpectedly")
                return False
                
            print("ZAP daemon appears to be running")
            return True
                
        print("ZAP JAR not found at specified path.")
        print(f"Please verify ZAP is installed at: {zap_jar}")
        return False
        
    except Exception as e:
        print(f"Failed to start ZAP daemon: {str(e)}")
        return False

def run_zap_scan(target_url: str, quick_scan: bool = False, timeout: int = 120) -> Optional[list]:
    if not validate_url(target_url):
        print(f"Invalid URL format: {target_url}")
        return None

    try:
        if not start_zap_daemon():
            return None

        print("Waiting for ZAP to initialize...")
        time.sleep(20)  # Increased initial wait time
        
        zap = ZAPv2(apikey=None, proxies={
            'http': 'http://127.0.0.1:8080',
            'https': 'http://127.0.0.1:8080'
        })
        
        # Remove the unsupported method calls
        # These lines can be safely removed as the alert threshold is already set in the daemon startup
        # zap.core.set_option_alert_threshold('MEDIUM')
        # zap.core.set_option_alert_overrides_enabled(True)
        
        # Test connection with retry
        start_time = time.time()
        connected = False
        while time.time() - start_time < timeout:
            try:
                version = zap.core.version
                print(f"ZAP {version} started successfully!")
                connected = True
                break
            except Exception as e:
                print(f"Waiting for ZAP to start... Retrying in 5 seconds")
                time.sleep(5)
        
        if not connected:
            print("Failed to connect to ZAP after timeout")
            return None
            
        try:
            # Access target
            print(f"Accessing target: {target_url}")
            zap.urlopen(target_url)
            time.sleep(1)

            # Configure scan based on mode
            if quick_scan:
                # Quick scan settings
                zap.spider.set_option_max_depth(3)
                zap.spider.set_option_max_duration(5)
                zap.ascan.set_option_max_scan_duration_in_mins(10)
                zap.ascan.set_option_thread_per_host(5)
            else:
                # Thorough scan settings
                zap.spider.set_option_max_depth(10)
                zap.spider.set_option_max_duration(0)  # No limit
                zap.ascan.set_option_max_scan_duration_in_mins(0)  # No limit
                zap.ascan.set_option_thread_per_host(2)

            # Spider scan
            print("Starting spider scan...")
            scan_id = zap.spider.scan(target_url)
            
            while int(zap.spider.status(scan_id)) < 100:
                status = zap.spider.status(scan_id)
                print(f"Spider progress: {status}%")
                time.sleep(2)
            
            # Give the passive scanner a chance to finish
            time.sleep(5)
            
            # Active scan
            print("Starting active scan...")
            ascan_id = zap.ascan.scan(target_url, recurse=True)
            
            while int(zap.ascan.status(ascan_id)) < 100:
                status = zap.ascan.status(ascan_id)
                print(f"Scan progress: {status}%")
                time.sleep(5)
            
            # Get all alerts
            print("\nGenerating Security Report...")
            alerts = zap.core.alerts()
            
            if alerts:
                print("\nVulnerabilities Found:")
                for alert in alerts:
                    print(f"\nRisk Level: {alert['risk']}")
                    print(f"Alert: {alert['name']}")
                    print(f"Description: {alert['description']}")
                    print(f"URL: {alert['url']}")
                    print("-" * 80)
            else:
                print("No vulnerabilities found.")
            
            return alerts
            
        finally:
            try:
                print("\nShutting down ZAP...")
                zap.core.shutdown()
            except:
                pass

    except Exception as e:
        print(f"Error during ZAP scan: {str(e)}")
        return None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='ZAP Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--quick', action='store_true', help='Run quick scan instead of thorough scan')
    
    args = parser.parse_args()
    
    print(f"Starting {'quick' if args.quick else 'thorough'} scan...")
    results = run_zap_scan(args.url, quick_scan=args.quick)
