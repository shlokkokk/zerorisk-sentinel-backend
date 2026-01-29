"""Optional AI explanation service for security analysis results"""

import os
from typing import Dict, Union
import logging
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ollama via ngrok tunnel (set in Render env vars)
MODEL = os.getenv("OLLAMA_MODEL", "huihui_ai/foundation-sec-abliterated")
TIMEOUT = 60

_STATIC_FALLBACK = (
    "AI explanation service is currently unavailable. "
    "Displaying heuristic-based analysis instead."
)


def _build_prompt(data: Dict) -> str:
    return f"""You are a cybersecurity educator explaining static heuristic security analysis results.

Analysis details:
- Type: {data.get('analysis_type', 'unknown')}
- Target: {data.get('target', 'unknown')}
- Threat score: {data.get('threat_score', 'N/A')} / 100
- Threat level: {data.get('threat_level', 'unknown')}
- Findings: {', '.join(data.get('findings', []))}

Explain what these indicators suggest in a measured, academic tone. Emphasize this is heuristic-based analysis, not proof of malicious intent. Keep under 120 words."""


def _call_ollama(prompt: str) -> str:
    """Call Ollama through ngrok tunnel."""
    host = os.getenv("OLLAMA_HOST", "")
    
    if not host:
        raise RuntimeError("OLLAMA_HOST not set. Configure in Render dashboard.")
    
    logger.info("OLLAMA | Calling %s with model: %s", host, MODEL)
    
    # Verify model exists
    try:
        resp = requests.get(f"{host}/api/tags", timeout=5)
        models = [m["name"] for m in resp.json().get("models", [])]
        if MODEL not in models and f"{MODEL}:latest" not in models:
            raise RuntimeError(f"Model {MODEL} not found in Ollama. Run: ollama pull {MODEL}")
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Cannot connect to Ollama at {host}. Is ngrok running?")

    # Generate
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.25,
            "num_predict": 200
        }
    }

    response = requests.post(
        f"{host}/api/generate",
        json=payload,
        timeout=TIMEOUT
    )
    response.raise_for_status()
    
    return response.json().get("response", "").strip()


def explain_with_ai(data: dict) -> Union[str, dict]:
    """Generate explanation using Ollama via ngrok."""
    try:
        prompt = _build_prompt(data)
        explanation = _call_ollama(prompt)
        
        if not explanation or len(explanation) < 10:
            raise ValueError("Empty model response")
            
        return explanation
        
    except Exception as e:
        logger.error("OLLAMA FAILED: %s", repr(e))
        return {
            "text": _STATIC_FALLBACK,
            "fallback": True
        }
