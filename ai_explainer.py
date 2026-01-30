"""AI explanation service using Groq API - free tier, no local hosting needed"""

import os
import logging
from typing import Dict, Union
from groq import Groq
from groq._exceptions import AuthenticationError, APIError, RateLimitError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment variables
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")  # Most capable

_STATIC_FALLBACK = (
    "AI explanation service is currently unavailable. "
    "Displaying heuristic-based analysis instead."
)


def _build_prompt(data: Dict) -> str:
    """Build cybersecurity analysis prompt from scan data."""
    analysis_type = data.get("analysis_type", "unknown")
    target = data.get("target", "unknown")
    threat_score = data.get("threat_score", "N/A")
    threat_level = data.get("threat_level", "unknown")
    findings = data.get("findings", [])
    
    findings_text = ", ".join(findings) if findings else "No specific findings"
    
    return f"""
You are a senior malware analyst assisting a security report.

Context:
This is a STATIC heuristic analysis of source code. No execution evidence is available.

Scan Summary:
- Target: {target}
- Threat Score: {threat_score}/100
- Threat Level: {threat_level}

Detected Indicators:
{chr(10).join(f"- {f}" for f in findings) if findings else "- None"}

Your task:
1. Identify which indicators are MOST critical and why.
2. Explain what functionality the code appears capable of.
3. Clarify what is UNKNOWN due to static-only analysis.
4. State what additional evidence would be required to confirm malicious intent.

Rules:
- Do NOT restate the scan summary.
- Do NOT give generic disclaimers.
- Be concise, analytical, and practical.
- Write like a security analyst briefing a developer/user.

Limit: ~100 words.
"""

def _validate_config() -> tuple[bool, str]:
    """Validate Groq configuration before making API calls."""
    if not GROQ_API_KEY:
        return False, "GROQ_API_KEY environment variable not set"
    
    if not GROQ_API_KEY.startswith("gsk_"):
        return False, "GROQ_API_KEY appears invalid (should start with 'gsk_')"
    
    return True, "OK"


def explain_with_ai(data: dict) -> Union[str, dict]:
    """
    Generate AI explanation using Groq API.
    
    Args:
        data: Dictionary containing analysis results
        
    Returns:
        str: AI explanation text on success
        dict: Fallback object with error details on failure
    """
    
    # Validate configuration first
    is_valid, error_msg = _validate_config()
    if not is_valid:
        logger.error(f"CONFIG ERROR: {error_msg}")
        return {
            "text": f"{_STATIC_FALLBACK} (Config: {error_msg})",
            "fallback": True,
            "error": error_msg
        }
    
    # Validate input data
    if not isinstance(data, dict):
        error_msg = "Invalid data format: expected dictionary"
        logger.error(error_msg)
        return {
            "text": _STATIC_FALLBACK,
            "fallback": True,
            "error": error_msg
        }
    
    try:
        # Initialize Groq client
        client = Groq(api_key=GROQ_API_KEY)
        
        # Build prompt
        prompt = _build_prompt(data)
        logger.info(f"GROQ | Sending request for: {data.get('target', 'unknown')}")
        
        # Make API call with timeout and error handling
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity analysis assistant. Explain technical findings clearly and concisely. Never claim certainty about malicious intent from static analysis alone."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model=MODEL,
            temperature=0.3,  # Low temperature for consistent, factual responses
            max_tokens=250,   # Enough for ~120 words + buffer
            timeout=30        # 30 second timeout
        )
        
        # Extract response
        explanation = chat_completion.choices[0].message.content.strip()
        
        # Validate response quality
        if not explanation:
            raise ValueError("Empty response from Groq API")
        
        if len(explanation) < 10:
            raise ValueError(f"Response too short ({len(explanation)} chars)")
        
        logger.info(f"GROQ | Success - received {len(explanation)} chars")
        return explanation
        
    except AuthenticationError as e:
        error_msg = "Invalid Groq API key"
        logger.error(f"GROQ AUTH ERROR: {e}")
        return {
            "text": f"{_STATIC_FALLBACK} (Authentication failed)",
            "fallback": True,
            "error": error_msg
        }
        
    except RateLimitError as e:
        error_msg = "Groq rate limit exceeded - try again in a moment"
        logger.error(f"GROQ RATE LIMIT: {e}")
        return {
            "text": f"{_STATIC_FALLBACK} (Rate limit exceeded)",
            "fallback": True,
            "error": error_msg
        }
        
    except APIError as e:
        error_msg = f"Groq API error: {str(e)}"
        logger.error(f"GROQ API ERROR: {e}")
        return {
            "text": _STATIC_FALLBACK,
            "fallback": True,
            "error": error_msg
        }
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(f"GROQ UNEXPECTED ERROR: {e}")
        return {
            "text": _STATIC_FALLBACK,
            "fallback": True,
            "error": error_msg
        }


