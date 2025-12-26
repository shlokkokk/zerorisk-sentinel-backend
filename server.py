import os
import tempfile
import uuid
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from apk_analyzer import analyze_apk

app = Flask(__name__)
CORS(app)

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
        analysis_result = analyze_apk(tmp_path)
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
