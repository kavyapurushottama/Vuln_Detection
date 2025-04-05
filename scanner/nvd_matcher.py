import nvdlib
import time
from datetime import datetime, timedelta

def match_with_cves(filepath):
    try:
        print(f"Starting CVE matching for: {filepath}")
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Initialize results list
        matched_cves = []
        
        # Search last 2 years of CVEs
        end_date = datetime.now()
        start_date = end_date - timedelta(days=730)
        
        # Convert dates to required format
        start_date_str = start_date.strftime("%Y-%m-%d")
        end_date_str = end_date.strftime("%Y-%m-%d")
        
        # Search NVD database
        results = nvdlib.searchCVE(
            pubStartDate=start_date_str,
            pubEndDate=end_date_str,
            keywordSearch=content,
            keywordExactMatch=False
        )
        
        for cve in results:
            severity = "Low"
            cvss_score = 'N/A'
            
            try:
                if hasattr(cve, 'score') and cve.score and len(cve.score) > 2:
                    score_value = cve.score[2]
                    if score_value is not None:
                        cvss_score = float(score_value)
                        if cvss_score >= 7.0:
                            severity = "High"
                        elif cvss_score >= 4.0:
                            severity = "Medium"
            except (TypeError, ValueError, IndexError):
                pass
            
            matched_cves.append({
                'file': str(filepath),
                'line': 'N/A',
                'cve': {
                    'id': getattr(cve, 'id', 'Unknown'),
                    'description': getattr(cve, 'overview', 'No description available'),
                    'cvss_score': cvss_score,
                    'risk': severity
                }
            })
            
            # Respect API rate limits
            time.sleep(0.6)
        
        print(f"Found {len(matched_cves)} CVE matches")
        return matched_cves
        
    except Exception as e:
        print(f"Error matching CVEs: {str(e)}")
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
