import json
from pathlib import Path
import re

def match_with_cves(filepath):
    try:
        print(f"Starting CVE matching for: {filepath}")
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
            lines = content.splitlines()
        
        db_path = Path(__file__).parent / 'data' / 'cve_database.json'
        if not db_path.exists():
            print("CVE database not found at:", db_path)
            return []
            
        with open(db_path, 'r', encoding='utf-8') as f:
            cve_db = json.load(f)
            
        matches = []
        for cve in cve_db:
            if not isinstance(cve, dict):
                continue
                
            patterns = cve.get('patterns', [])
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append({
                            'file': str(filepath),
                            'line': line_num,
                            'code': line.strip(),
                            'cve': {
                                'id': cve.get('id', 'Unknown'),
                                'description': cve.get('description', 'No description available'),
                                'cvss_score': cve.get('cvss_score', 'N/A'),
                                'risk': cve.get('risk', 'Medium')
                            }
                        })
        
        print(f"Found {len(matches)} CVE matches")
        return matches
        
    except Exception as e:
        print(f"Error in CVE matching: {str(e)}")
        return []

def calculate_risk_level(cvss_score):
    """Calculate risk level based on CVSS score"""
    try:
        score = float(cvss_score)
        if score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    except (ValueError, TypeError):
        return 'Low'
