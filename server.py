import os
import tempfile
import uuid
import logging

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_STATIC_FALLBACK = (
    "AI explanation service is currently unavailable. "
    "Displaying heuristic-based analysis instead."
)
try:
    from url_scanner import scan_url, URLScanner
    URL_SCANNER_AVAILABLE = True
    logger.info("[INIT] URL scanner loaded")
except ImportError as e:
    URL_SCANNER_AVAILABLE = False
    logger.warning(f"[INIT] URL scanner not available: {e}")
# Import file scanner 
try:
    from file_scanner import scan_file, get_scanner, FileScanner
    FILE_SCANNER_AVAILABLE = True
    logger.info("[INIT] File scanner loaded successfully")
except ImportError as e:
    FILE_SCANNER_AVAILABLE = False
    logger.warning(f"[INIT] File scanner not available: {e}")


def analyze_apk_safe(path):
    from apk_analyzer import analyze_apk
    return analyze_apk(path)


def explain_with_ai_safe(data):
    from ai_explainer import explain_with_ai
    return explain_with_ai(data)


app = Flask(__name__)

# CORS setup
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)


@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# Configuration
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
ALLOWED_EXTENSIONS = {'apk'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/status', methods=['GET'])
def status():
    """Updated status endpoint with file scanner and sandbox info"""
    scanner = get_scanner() if FILE_SCANNER_AVAILABLE else None
    
    features = ["apk_analysis", "ai_explanation"]
    if FILE_SCANNER_AVAILABLE:
        features.append("file_scanning")
        features.append("yara_rules")
        features.append("virustotal")
    
    # Check sandbox availability
    hybrid_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
    sandbox_available = bool(hybrid_key)
    if sandbox_available:
        features.append("sandbox")
    
    return jsonify({
        "backend": "online",
        "features": features,
        "file_scanner": {
            "available": FILE_SCANNER_AVAILABLE,
            "yara_loaded": scanner.yara_rules is not None if scanner else False,
            "virustotal_configured": bool(os.getenv("VIRUSTOTAL_API_KEY", ""))
        },
        "sandbox": {
            "available": sandbox_available,
            "provider": "hybrid_analysis" if sandbox_available else None,
            "configured": sandbox_available
        }
    }), 200

# NEW ENDPOINT: General File Scanning
@app.route('/api/scan-file', methods=['POST'])
def scan_file_endpoint():
    """
    Scan any file for malware using YARA rules, entropy analysis, 
    file hashing, and VirusTotal lookup.
    """
    if not FILE_SCANNER_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "File scanner not available. Check server logs."
        }), 503
    
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4()}_{filename}")

    try:
        # Save uploaded file
        file.save(tmp_path)
        file_size = os.path.getsize(tmp_path)
        
        logger.info(f"[SCAN-FILE] Received: {filename} ({file_size} bytes)")
        
        # Scan the file
        scan_result = scan_file(tmp_path, filename)
        
        return jsonify({
            "success": True,
            "data": scan_result
        }), 200
        
    except Exception as e:
        logger.error(f"[SCAN-FILE] ERROR: {e}")
        return jsonify({
            "success": False,
            "error": f"File scan failed: {str(e)}"
        }), 500
        
    finally:
        # Cleanup
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if os.path.exists(tmp_dir):
                os.rmdir(tmp_dir)
        except Exception as cleanup_error:
            logger.warning(f"[SCAN-FILE] Cleanup error: {cleanup_error}")


# NEW ENDPOINT: Hash Lookup (no file upload)
@app.route('/api/scan-hash/<file_hash>', methods=['GET'])
def scan_hash_endpoint(file_hash):
    """
    Check a file hash against VirusTotal without uploading the file.
    Supports MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars).
    """
    if not FILE_SCANNER_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "File scanner not available"
        }), 503
    
    # Validate hash length
    if len(file_hash) not in [32, 40, 64]:
        return jsonify({
            "success": False,
            "error": "Invalid hash length. Expected MD5 (32), SHA1 (40), or SHA256 (64)"
        }), 400
    
    try:
        scanner = get_scanner()
        vt_result = scanner.check_virustotal(file_hash)
        
        return jsonify({
            "success": True,
            "data": {
                "hash": file_hash,
                "virustotal": vt_result
            }
        }), 200
        
    except Exception as e:
        logger.error(f"[SCAN-HASH] ERROR: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/analyze-apk', methods=['POST'])
def analyze_apk_endpoint():
    """Existing APK analysis endpoint"""
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": "Invalid file type. Only .apk files are allowed"}), 400

    filename = secure_filename(file.filename)
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4()}_{filename}")

    try:
        file.save(tmp_path)
        analysis_result = analyze_apk_safe(tmp_path)
        return jsonify({"success": True, "data": analysis_result}), 200
    except Exception as e:
        logger.error(f"APK ANALYSIS ERROR: {e}")
        return jsonify({
            "success": False,
            "error": "APK analysis failed due to server-side processing error"
        }), 500
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if os.path.exists(tmp_dir):
                os.rmdir(tmp_dir)
        except Exception as cleanup_error:
            logger.warning(f"Cleanup error: {cleanup_error}")

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url_endpoint():
    """Analyze URL with 15 second timeout for all checks"""
    if not URL_SCANNER_AVAILABLE:
        return jsonify({"success": False, "error": "URL scanner not available"}), 503
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"success": False, "error": "No URL provided"}), 400
    
    url = data['url']
    logger.info(f"[URL-API] Analyzing: {url}")
    
    try:
        result = scan_url(url)
        return jsonify({"success": True, "data": result}), 200
    except Exception as e:
        logger.error(f"[URL-API] Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    
@app.route('/api/ai-explain', methods=['POST', 'OPTIONS'])
def ai_explain():
    """AI explanation endpoint with proper error handling."""
    
    # Handle CORS preflight FIRST
    if request.method == 'OPTIONS':
        response = jsonify({"success": True})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response, 200

    try:
        # Parse JSON body
        data = request.get_json(silent=True)
        
        if not data:
            return jsonify({
                "success": False,
                "error": "No JSON data provided",
                "fallback": True,
                "ai_explanation": _STATIC_FALLBACK
            }), 400
        
        # Validate required fields
        required_fields = ['analysis_type', 'target']
        missing_fields = [f for f in required_fields if f not in data]
        
        if missing_fields:
            return jsonify({
                "success": False,
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "fallback": True,
                "ai_explanation": _STATIC_FALLBACK
            }), 400
        
        # Call AI explainer
        explanation = explain_with_ai_safe(data)
        
        # Check if we got a fallback response
        if isinstance(explanation, dict) and explanation.get("fallback") is True:
            return jsonify({
                "success": False,
                "fallback": True,
                "ai_explanation": explanation.get("text", _STATIC_FALLBACK),
                "error": explanation.get("error", "AI service unavailable")
            }), 200
        
        # Success - real AI response
        return jsonify({
            "success": True,
            "fallback": False,
            "ai_explanation": explanation
        }), 200
        
    except Exception as e:
        logger.error(f"AI EXPLAIN ENDPOINT ERROR: {e}")
        return jsonify({
            "success": False,
            "fallback": True,
            "ai_explanation": _STATIC_FALLBACK,
            "error": "Internal server error"
        }), 500

#urlscan endpoint
@app.route('/api/urlscan/submit', methods=['POST'])
def urlscan_submit():
    """Submit URL to urlscan.io sandbox"""
    try:
        from url_scanner import submit_urlscan
        
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'success': False, 'error': 'No URL provided'}), 400
        
        url = data['url']
        logger.info(f"[URLSCAN] Submitting: {url}")
        
        result = submit_urlscan(url)
        return jsonify(result), 200 if result.get('success') else 500
        
    except Exception as e:
        logger.error(f"[URLSCAN] Submit error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/urlscan/result/<scan_id>', methods=['GET'])
def urlscan_result(scan_id):
    """Get urlscan.io scan result"""
    try:
        from url_scanner import get_urlscan_result
        
        logger.info(f"[URLSCAN] Polling result: {scan_id}")
        
        result = get_urlscan_result(scan_id)
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"[URLSCAN] Result error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# SANDBOX FILE SCAN ENDPOINTS
@app.route('/api/sandbox/submit', methods=['POST'])
def sandbox_submit():
    """Submit file to Hybrid Analysis sandbox for deep scanning"""
    try:
        from sandbox_scanner import submit_to_sandbox
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Empty filename'}), 400
        
        filename = secure_filename(file.filename)
        tmp_dir = tempfile.mkdtemp()
        tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4()}_{filename}")
        
        file.save(tmp_path)
        
        logger.info(f"[SANDBOX] Submitting {filename} to Hybrid Analysis")
        result = submit_to_sandbox(tmp_path, filename)
        
        # Cleanup
        try:
            os.remove(tmp_path)
            os.rmdir(tmp_dir)
        except:
            pass
        
        return jsonify(result), 200 if result.get('success') else 500
        
    except Exception as e:
        logger.error(f"[SANDBOX] Submit error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sandbox/result/<job_id>', methods=['GET'])
def sandbox_result(job_id):
    """Get Hybrid Analysis sandbox result AND merge with regular scan"""
    try:
        from sandbox_scanner import get_sandbox_result
        from file_scanner import scan_file, get_scanner
        
        logger.info(f"[SANDBOX] Polling result: {job_id}")
        
        sandbox_data = get_sandbox_result(job_id)
        
        # If sandbox completed, we need to also run the regular scan
        # But we don't have the file anymore, so we return sandbox-only data
        # The frontend will handle merging if it has the regular scan cached
        
        return jsonify(sandbox_data), 200
        
    except Exception as e:
        logger.error(f"[SANDBOX] Result error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan-file-deep', methods=['POST'])
def scan_file_deep_endpoint():
    """
    DEEP FILE SCAN: Regular scan + submit to sandbox
    Returns regular results immediately with sandbox job_id for polling
    """
    if not FILE_SCANNER_AVAILABLE:
        return jsonify({
            "success": False,
            "error": "File scanner not available"
        }), 503
    
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file"}), 400
    
    filename = secure_filename(file.filename)
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, f"{uuid.uuid4()}_{filename}")
    
    try:
        # Save file
        file.save(tmp_path)
        logger.info(f"[DEEP-SCAN] Starting deep scan of: {filename}")
        
        #  Run regular scan first
        from file_scanner import scan_file
        regular_result = scan_file(tmp_path, filename)
        
        #  Submit to sandbox
        from sandbox_scanner import submit_to_sandbox
        sandbox_submit_result = submit_to_sandbox(tmp_path, filename)
        
        # Combine results
        response = {
            "success": True,
            "regular_scan": regular_result,
            "sandbox": sandbox_submit_result
        }
        
        # If sandbox submission failed, still return regular scan
        if not sandbox_submit_result.get('success'):
            response['sandbox_error'] = sandbox_submit_result.get('error')
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"[DEEP-SCAN] ERROR: {e}")
        return jsonify({
            "success": False,
            "error": f"Deep scan failed: {str(e)}"
        }), 500
        
    finally:
        # Cleanup
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if os.path.exists(tmp_dir):
                os.rmdir(tmp_dir)
        except Exception as cleanup_error:
            logger.warning(f"[DEEP-SCAN] Cleanup error: {cleanup_error}")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)