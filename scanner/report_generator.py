from datetime import datetime
from pathlib import Path

def generate_html_report(scan_type, bandit_issues=None, matched_cves=None, zap_results=None, scan_mode=None):
    try:
        # Change timestamp format to be more readable for display
        display_timestamp = datetime.now().strftime("%B %d, %Y at %I:%M:%S %p")
        
        reports_dir = Path(__file__).parent.parent / 'static' / 'reports'
        reports_dir.mkdir(exist_ok=True, parents=True)
        output_path = reports_dir / 'report.html'  # Fixed filename
        
        print(f"Generating report at: {output_path}")
        print(f"Scan type: {scan_type}")
        print(f"Bandit issues: {len(bandit_issues) if bandit_issues else 0}")
        print(f"CVE matches: {len(matched_cves) if matched_cves else 0}")
        
        html_content = f"""
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; text-align: center; }}
                h2 {{ color: #555; margin-top: 30px; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 40px; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .risk-high {{ color: #fff; background-color: #e74c3c; padding: 5px 10px; border-radius: 4px; }}
                .risk-medium {{ color: #fff; background-color: #e67e22; padding: 5px 10px; border-radius: 4px; }}
                .risk-low {{ color: #fff; background-color: #2ecc71; padding: 5px 10px; border-radius: 4px; }}
                /* Add column width specifications */
                .alert-column {{ width: 40%; }}
                .url-column {{ width: 25%; }}
                .evidence-column {{ width: 10%; }}
                .description {{ font-size: 0.9em; color: #666; }}
                td.alert-column {{ max-width: 300px; word-wrap: break-word; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Scan Report</h1>
            <div id="scan-info">
                <p>Scan Type: {scan_type.capitalize()} {f'({scan_mode} Scan)' if scan_mode else ''}</p>
                <p>Generated: {display_timestamp}</p>
            </div>
        """

        if scan_type == 'file':
            print(f"Processing Bandit issues: {len(bandit_issues) if bandit_issues else 0}")
            if bandit_issues:
                html_content += generate_bandit_section(bandit_issues)
            print(f"Processing CVE matches: {len(matched_cves) if matched_cves else 0}")
            if matched_cves:
                html_content += generate_cve_section(matched_cves)
            if not bandit_issues and not matched_cves:
                html_content += "<h2>No vulnerabilities found in the file.</h2>"
                
        elif scan_type == 'website' and zap_results:
            html_content += generate_zap_section(zap_results)
        else:
            html_content += "<h2>No vulnerabilities found.</h2>"

        html_content += "</body></html>"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"Report generated successfully at: {output_path}")
        # Return fixed filename
        return 'report.html'
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return None

def generate_bandit_section(issues):
    if not issues:
        return "<h2>No Bandit issues found.</h2>"
        
    html = """
        <h2>Bandit Security Issues</h2>
        <table>
            <tr>
                <th>File</th>
                <th>Line</th>
                <th>Issue</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Confidence</th>
            </tr>
    """
    
    # Severity and confidence score mappings
    severity_scores = {
        'HIGH': 9.0,
        'MEDIUM': 6.0,
        'LOW': 3.0
    }
    
    confidence_multiplier = {
        'HIGH': 1.0,
        'MEDIUM': 0.8,
        'LOW': 0.5
    }
    
    for issue in issues:
        severity = issue.get('issue_severity', 'LOW').upper()
        confidence = issue.get('issue_confidence', 'LOW').upper()
        
        # Calculate numerical score
        base_score = severity_scores.get(severity, 3.0)
        multiplier = confidence_multiplier.get(confidence, 0.5)
        final_score = round(base_score * multiplier, 1)
        
        risk_class = 'risk-low'
        if final_score >= 7.6:
            risk_class = 'risk-high'
        elif final_score >= 4.1:
            risk_class = 'risk-medium'
            
        html += f"""
        <tr>
            <td>{issue.get('filename', 'N/A')}</td>
            <td>{issue.get('line_number', 'N/A')}</td>
            <td>{issue.get('issue_text', 'N/A')}</td>
            <td><span class="{risk_class}">{severity}</span></td>
            <td>{final_score}</td>
            <td><span class="{risk_class}">{confidence}</span></td>
        </tr>
        """
    
    html += "</table>"
    return html

def generate_cve_section(cves):
    if not cves:
        return "<h2>No CVE matches found.</h2>"
        
    html = """
        <h2>CVE Matches</h2>
        <table>
            <tr>
                <th>File</th>
                <th>Line</th>
                <th>CVE ID</th>
                <th>Description</th>
                <th>CVSS Score</th>
                <th>Risk Level</th>
            </tr>
    """
    
    for match in cves:
        cve_info = match.get('cve', {})
        risk_level = cve_info.get('risk', 'Low')
        risk_class = 'risk-low'
        if risk_level.lower() == 'high':
            risk_class = 'risk-high'
        elif risk_level.lower() == 'medium':
            risk_class = 'risk-medium'
            
        html += f"""
        <tr>
            <td>{match.get('file', 'N/A')}</td>
            <td>{match.get('line', 'N/A')}</td>
            <td>{cve_info.get('id', 'N/A')}</td>
            <td>{cve_info.get('description', 'N/A')}</td>
            <td>{cve_info.get('cvss_score', 'N/A')}</td>
            <td><span class="{risk_class}">{risk_level}</span></td>
        </tr>
        """
    
    html += "</table>"
    return html

def generate_zap_section(results):
    html = """
        <h2>Website Vulnerability Scan (ZAP)</h2>
        <table class="zap-table">
            <tr>
                <th class="alert-column">Alert</th>
                <th>Risk</th>
                <th class="url-column">URL</th>
                <th>Parameter</th>
                <th class="evidence-column">Evidence</th>
            </tr>
    """
    
    for alert in results:
        risk_level = alert.get('risk', 'Low')
        risk_class = 'risk-low' if risk_level == 'Low' else 'risk-medium' if risk_level == 'Medium' else 'risk-high'
        html += f"""
        <tr>
            <td class="alert-column"><strong>{alert.get('name', alert.get('alert', 'N/A'))}</strong><br>
            <span class="description">{alert.get('description', 'N/A')}</span></td>
            <td><span class="{risk_class}">{risk_level}</span></td>
            <td class="url-column">{alert.get('url', 'N/A')}</td>
            <td>{alert.get('param', 'N/A')}</td>
            <td class="evidence-column">{alert.get('evidence', 'N/A')}</td>
        </tr>
        """
    
    html += "</table>"
    return html