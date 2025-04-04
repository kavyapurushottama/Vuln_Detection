from scanner import bandit_scanner, nvd_matcher, report_generator, zap_scanner
import argparse

def main():
    parser = argparse.ArgumentParser(description='Vulnerability Scanner CLI')
    parser.add_argument('--path', default='test_code/', help='Path to code directory to scan')
    parser.add_argument('--url', default='http://testphp.vulnweb.com', help='URL to scan')
    args = parser.parse_args()

    print(f"Starting scan for path: {args.path}")
    print(f"Target URL: {args.url}")

    print("\nRunning Bandit Scan...")
    issues = bandit_scanner.run_bandit_scan(args.path)
    print(f"Found {len(issues)} issues.")

    print("\nMatching with CVEs...")
    matched_cves = nvd_matcher.match_with_cves(issues)
    print(f"Found {len(matched_cves)} matching CVEs.")

    print("\nRunning ZAP scan...")
    try:
        zap_results = zap_scanner.run_zap_scan(args.url)
        if zap_results is not None:
            print(f"Found {len(zap_results)} ZAP alerts.")
        else:
            print("ZAP scan failed to produce results")
            zap_results = []
    except Exception as e:
        print(f"ZAP scan failed: {str(e)}")
        zap_results = []

    print("\nGenerating report...")
    report_file = report_generator.generate_html_report('cli', bandit_issues=issues, 
                                                      matched_cves=matched_cves, 
                                                      zap_results=zap_results)
    if report_file:
        print(f"Report generated successfully: {report_file}")
    else:
        print("Failed to generate report")

if __name__ == "__main__":
    main()
