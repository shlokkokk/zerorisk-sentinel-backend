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
    """Updated status endpoint with file scanner info"""
    scanner = get_scanner() if FILE_SCANNER_AVAILABLE else None
    
    features = ["apk_analysis", "ai_explanation"]
    if FILE_SCANNER_AVAILABLE:
        features.append("file_scanning")
        features.append("yara_rules")
        features.append("virustotal")
    
    return jsonify({
        "backend": "online",
        "features": features,
        "file_scanner": {
            "available": FILE_SCANNER_AVAILABLE,
            "yara_loaded": scanner.yara_rules is not None if scanner else False,
            "virustotal_configured": bool(os.getenv("VIRUSTOTAL_API_KEY", ""))
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


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)