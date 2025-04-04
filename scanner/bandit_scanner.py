import subprocess
import json
import sys
from pathlib import Path

def run_bandit_scan(filepath):
    try:
        print(f"Running Bandit scan on: {filepath}")
        
        # Run bandit with basic options and no config file
        cmd = ['bandit', '-f', 'json', filepath]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                results = data.get('results', [])
                print(f"Found {len(results)} potential vulnerabilities")
                if results:
                    for issue in results:
                        print(f"Found issue: {issue.get('issue_text')} at line {issue.get('line_number')}")
                return results
            except json.JSONDecodeError as e:
                print(f"JSON parse error: {e}")
        
        if result.stderr:
            print(f"Bandit error: {result.stderr}")
            
        return []
            
    except Exception as e:
        print(f"Error in Bandit scan: {str(e)}")
        return []

