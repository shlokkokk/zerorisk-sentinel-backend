import os
import tempfile
import uuid

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
def analyze_apk_lazy(path):
    from apk_analyzer import analyze_apk
    return analyze_apk(path)

def explain_with_ai_lazy(data):
    from ai_explainer import explain_with_ai
    return explain_with_ai(data)


app = Flask(__name__)
CORS(app)
CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=True
)

@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
ALLOWED_EXTENSIONS = {'apk'}

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "backend": "online",
        "features": ["apk_analysis", "http_status_analysis"]
    }), 200

@app.route('/api/analyze-apk', methods=['POST'])
def analyze_apk_endpoint():
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
        analysis_result = analyze_apk_lazy(tmp_path)
        return jsonify({"success": True, "data": analysis_result}), 200
    except Exception as e:
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
        except Exception:
            pass
@app.route('/api/ai-explain', methods=['POST', 'OPTIONS'])
def ai_explain():
    #  Handle CORS preflight FIRST
    if request.method == 'OPTIONS':
        return jsonify({"success": True}), 200

    try:
        # prevents Flask from throwing on empty body
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "success": False,
                "error": "No analysis data provided"
            }), 400

        explanation = explain_with_ai_lazy(data)

        return jsonify({
            "success": True,
            "ai_explanation": explanation
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "AI explanation service unavailable"
        }), 503

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)





