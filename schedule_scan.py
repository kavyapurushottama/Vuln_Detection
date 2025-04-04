import time
import subprocess
import sys
from datetime import datetime
import argparse

def run_scheduled_scan(interval_minutes=10, max_retries=3):
    while True:
        try:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[{current_time}] Starting scheduled scan...")
            
            result = subprocess.run(
                [sys.executable, "main.py"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"[{current_time}] Scan completed successfully")
            else:
                print(f"[{current_time}] Scan failed with error:\n{result.stderr}")
                
        except Exception as e:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}] Error running scan: {str(e)}")
            
        print(f"Waiting {interval_minutes} minutes until next scan...")
        time.sleep(interval_minutes * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scheduled Vulnerability Scanner')
    parser.add_argument('--interval', type=int, default=10,
                      help='Scan interval in minutes (default: 10)')
    parser.add_argument('--retries', type=int, default=3,
                      help='Maximum retry attempts for failed scans (default: 3)')
    
    args = parser.parse_args()
    
    print(f"Starting scheduled scanner with {args.interval} minute intervals")
    run_scheduled_scan(args.interval, args.retries)
