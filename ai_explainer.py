"""

Optional AI explanation service for security analysis results

"""

import os
from typing import Dict
import openai
from openai import OpenAI

# Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL = "gpt-4o-mini"
TEMPERATURE = 0.25
TIMEOUT = 5  # seconds

_STATIC_FALLBACK = (
    "AI explanation service is currently unavailable. "
    "Displaying heuristic-based analysis instead."
)

def _build_prompt(data: Dict) -> str:
    return f"""
You are a cybersecurity educator explaining the results of a static, heuristic-based security analysis.

Base your explanation strictly on the provided findings and scores.
Describe what these indicators suggest in a measured, academic tone, without assuming intent or execution.
Focus on interpretation rather than verdicts, and clearly frame the analysis as indicative rather than definitive.

Analysis details:
- Type: {data.get('analysis_type', 'unknown')}
- Target: {data.get('target', 'unknown')}
- Threat score: {data.get('threat_score', 'N/A')} / 100
- Threat level: {data.get('threat_level', 'unknown')}
- Findings: {', '.join(data.get('findings', []))}

Produce a short paragraph (≤120 words) explaining why these findings matter, while emphasizing that the analysis is heuristic-based and not proof of malicious intent.
""".strip()



def _call_openai(prompt: str) -> str:
    """
    Call OpenAI with timeout and minimal cost settings.
    Raises on any failure so caller can fallback.
    """
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY not set")

    client = OpenAI(api_key=OPENAI_API_KEY, timeout=TIMEOUT)

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": "You are a cybersecurity educator."},
            {"role": "user", "content": prompt},
        ],
        temperature=TEMPERATURE,
        max_tokens=180,  # ~120 words
    )
    return response.choices[0].message.content.strip()


# Public API
def explain_with_ai(data: dict) -> str:
    """
    Generate a human-readable explanation of heuristic security findings.

    Parameters
    ----------
    data : dict
        Must contain keys:
        - analysis_type : str
        - target : str
        - threat_score : int  (0-100)
        - threat_level : str  ('safe', 'low', 'medium', 'high', 'critical')
        - findings : list[str]

    Returns
    -------
    str
        Plain-text explanation.  If the AI service fails, a static fallback
        message is returned.
    """
    try:
        prompt = _build_prompt(data)
        explanation = _call_openai(prompt)
        return explanation
    except Exception:
        # Any failure: network, auth, timeout, parsing, etc.
        return _STATIC_FALLBACK