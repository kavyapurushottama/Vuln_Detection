from flask import Flask, render_template, request, jsonify, send_from_directory, abort
import time 
from scanner.zap_scanner import run_zap_scan
from scanner.bandit_scanner import run_bandit_scan
from scanner.nvd_matcher import match_with_cves
from scanner.report_generator import generate_html_report
from werkzeug.utils import secure_filename
from pathlib import Path
from urllib.parse import urlparse
import os

# Configure paths and constants first
BASE_DIR = Path(__file__).parent
UPLOAD_FOLDER = BASE_DIR / 'uploads'
REPORTS_FOLDER = BASE_DIR / 'static' / 'reports'
ALLOWED_EXTENSIONS = {'py', 'js', 'php', 'java', 'cpp', 'c', 'rb'}

# Initialize Flask
app = Flask(__name__, 
           static_url_path='/static',
           static_folder=str(BASE_DIR / 'static'))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['REPORTS_FOLDER'] = str(REPORTS_FOLDER)
                                                
# Create necessary directories
UPLOAD_FOLDER.mkdir(exist_ok=True)
REPORTS_FOLDER.mkdir(exist_ok=True, parents=True)

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

@app.route('/scan_url', methods=['POST'])
def scan_url():
    try:
        start_time = time.time()
        url = request.form.get('url')
        scan_type = request.form.get('scan_type', 'thorough')
        
        if not url:
            return jsonify({'error': 'No URL provided'})
            
        if not validate_url(url):
            return jsonify({'error': 'Invalid URL format'})
        
        zap_results = run_zap_scan(url, quick_scan=(scan_type == 'quick'))
        
        if zap_results is None:
            return jsonify({'error': 'ZAP scan failed or no results found'})
        
        # Modified this line to pass scan_mode instead of scan_type
        report_filename = generate_html_report(
            scan_type='website',
            zap_results=zap_results,
            scan_mode=scan_type.capitalize()  # Pass as separate parameter
        )
        
        if report_filename:
            scan_duration = round(time.time() - start_time, 2)
            return jsonify({
                'status': 'success',
                'message': f'Website {scan_type} scan completed successfully, Took {scan_duration} seconds',
                'reportUrl': f'/static/reports/{report_filename}',
                'duration': scan_duration
            })
        
        return jsonify({'error': 'Failed to generate report'})
        
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'})

@app.route('/scan_file', methods=['POST'])
def scan_file():
    try:
        start_time = time.time()  # Start timing
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'})
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'})
            
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'})
            
        filename = secure_filename(file.filename)
        filepath = UPLOAD_FOLDER / filename
        file.save(str(filepath))
        
        try:
            bandit_results = run_bandit_scan(str(filepath))
            cve_matches = match_with_cves(str(filepath))
            
            report_filename = generate_html_report('file', 
                                           bandit_issues=bandit_results,
                                           matched_cves=cve_matches)
            
            # Clean up uploaded file
            os.remove(str(filepath))
            
            if report_filename:
                scan_duration = round(time.time() - start_time, 2)  # Calculate duration
                return jsonify({
                    'status': 'success',
                    'message': f'File scan completed successfully, Took {scan_duration} seconds',
                    'reportUrl': f'/static/reports/{report_filename}',
                    'duration': scan_duration
                })
            
            return jsonify({'error': 'Failed to generate report'})
            
        finally:
            if filepath.exists():
                os.remove(str(filepath))
                
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'})

# Remove the duplicate route and keep only this one
@app.route('/reports/<path:filename>')
def serve_report(filename):
    try:
        # Add content type for HTML files
        return send_from_directory(str(REPORTS_FOLDER), filename, mimetype='text/html')
    except Exception as e:
        print(f"Error serving report: {str(e)}")
        abort(404)

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Report not found'}), 404

@app.errorhandler(413)
def too_large_error(error):
    return jsonify({'error': 'File too large'}), 413

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=False, port=5000)
