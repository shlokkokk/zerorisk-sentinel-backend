import re
import json
import logging
import os
from typing import Dict, List, Any, Optional

from androguard.core.apk import APK

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

PERMISSION_RULES = [
    {
        "pattern": r"^android\.permission\.(READ_SMS|RECEIVE_SMS)$",
        "severity": "critical",
        "reason": "Access to SMS messages may lead to interception of sensitive data like OTPs."
    },
    {
        "pattern": r"^android\.permission\.BIND_ACCESSIBILITY_SERVICE$",
        "severity": "critical",
        "reason": "Can observe and interact with UI elements across all apps, enabling keylogging or phishing."
    },
    {
        "pattern": r"^android\.permission\.SYSTEM_ALERT_WINDOW$",
        "severity": "high",
        "reason": "Allows drawing overlay windows, potentially used for clickjacking or phishing."
    },
    {
        "pattern": r"^android\.permission\.(RECORD_AUDIO|CAMERA)$",
        "severity": "high",
        "reason": "Access to microphone or camera can lead to unauthorized surveillance."
    },
    {
        "pattern": r"^android\.permission\.REQUEST_INSTALL_PACKAGES$",
        "severity": "high",
        "reason": "Allows installation of arbitrary APKs, enabling malware deployment."
    },
    {
        "pattern": r"^android\.permission\.BIND_DEVICE_ADMIN$",
        "severity": "critical",
        "reason": "Grants device admin privileges, enabling remote lock/wipe or policy enforcement."
    },
    {
        "pattern": r"^android\.permission\.BIND_VPN_SERVICE$",
        "severity": "high",
        "reason": "Can intercept and redirect all network traffic, leading to data leaks."
    },
    {
        "pattern": r"^android\.permission\.RECEIVE_BOOT_COMPLETED$",
        "severity": "medium",
        "reason": "Ensures app starts on boot, often used by persistent malware."
    },
    {
        "pattern": r"^android\.permission\.READ_CONTACTS$",
        "severity": "medium",
        "reason": "Access to contact list can lead to privacy breaches and spam."
    },
    {
        "pattern": r"^android\.permission\.INTERNET$",
        "severity": "low",
        "reason": "Basic network access; risk depends on other permissions and behavior."
    },
    {
        "pattern": r"^android\.permission\.READ_PHONE_STATE$",
        "severity": "medium",
        "reason": "Access to device identifiers and call state, useful for tracking."
    },
    {
        "pattern": r"^android\.permission\.MANAGE_EXTERNAL_STORAGE$",
        "severity": "high",
        "reason": "Full access to external storage, enabling data theft or ransomware."
    }
]

SEVERITY_SCORE = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "low": 5
}

def determine_risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 15:
        return "low"
    return "safe"

def analyze_permissions(permissions: List[str]) -> List[Dict[str, str]]:
    risky = []

    for perm in permissions:
        for rule in PERMISSION_RULES:
            if re.search(rule["pattern"], perm):
                risky.append({
                    "permission": perm,
                    "severity": rule["severity"],
                    "reason": rule["reason"]
                })

    return risky

def calculate_risk_score(risky_permissions: List[Dict[str, str]]) -> int:
    score = 0
    for rp in risky_permissions:
        score += SEVERITY_SCORE.get(rp["severity"], 0)
    return min(score, 100)

def generate_explanation(risk_level: str, score: int, risky_count: int) -> str:
    if risk_level == "safe":
        return "No significant risky permissions detected. APK appears safe from a permission standpoint."
    return (
        f"Detected {risky_count} risky permission(s) with a total risk score of {score}. "
        f"Risk level is '{risk_level}'. Review risky permissions for potential security concerns."
    )

def analyze_apk(file_path: str) -> Dict[str, Any]:
    """
    MERGED: APK permissions + file scanner (hashes, entropy, VirusTotal)
    """
    # Try to import file scanner
    try:
        from file_scanner import scan_file
        FILE_SCANNER_AVAILABLE = True
    except ImportError:
        FILE_SCANNER_AVAILABLE = False
    
    # Result with ALL fields (APK + file scanner)
    result = {
        "apk_metadata": {},
        "permissions_detected": [],
        "risky_permissions": [],
        "risk_score": 0,
        "risk_level": "safe",
        "explanation": "",
        # NEW: File scanner fields
        "hashes": {},
        "entropy": 0.0,
        "file_type": {},
        "virustotal": None,
        "findings": []
    }
    
    try:
        apk = APK(file_path)
    except Exception as e:
        logger.error("Failed to load APK: %s", e)
        result["explanation"] = "Failed to analyze APK - malformed file"
        # Still try file scanner
        if FILE_SCANNER_AVAILABLE:
            file_data = scan_file(file_path, os.path.basename(file_path))
            result["hashes"] = file_data.get("hashes", {})
            result["entropy"] = file_data.get("entropy", 0)
            result["virustotal"] = file_data.get("virustotal")
        return result

    # Extract APK data
    try:
        result["apk_metadata"] = {
            "package_name": apk.get_package(),
            "version_name": apk.get_androidversion_name() or "",
            "version_code": apk.get_androidversion_code() or "",
            "min_sdk": apk.get_min_sdk_version() or "",
            "target_sdk": apk.get_target_sdk_version() or "",
            "activities": apk.get_activities() or [],
            "services": apk.get_services() or [],
            "receivers": apk.get_receivers() or []
        }
        result["permissions_detected"] = apk.get_permissions() or []
    except Exception as e:
        logger.error("Error extracting APK metadata: %s", e)
        result["explanation"] = "Partial analysis due to extraction errors"

    # Analyze permissions
    risky = analyze_permissions(result["permissions_detected"])
    result["risky_permissions"] = risky
    result["risk_score"] = calculate_risk_score(risky)

    # Permission combo heuristics
    perms = result["permissions_detected"]
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms and \
       "android.permission.SYSTEM_ALERT_WINDOW" in perms:
        result["risk_score"] += 25
    if "android.permission.RECEIVE_BOOT_COMPLETED" in perms and \
       "android.permission.INTERNET" in perms:
        result["risk_score"] += 15
    
    result["risk_score"] = min(result["risk_score"], 100)

    if FILE_SCANNER_AVAILABLE:
        try:
            filename = os.path.basename(file_path)
            file_data = scan_file(file_path, filename)
            
            # Merge file scanner results
            result["hashes"] = file_data.get("hashes", {})
            result["entropy"] = file_data.get("entropy", 0.0)
            result["file_type"] = file_data.get("file_type", {})
            result["virustotal"] = file_data.get("virustotal")
            
            # Add important findings
            for finding in file_data.get("findings", []):
                if finding.get("severity") in ["medium", "high", "critical"]:
                    result["findings"].append(finding)
            
            # BOOST SCORE if VirusTotal shows malware
            vt = result.get("virustotal")
            if vt and vt.get("found"):
                malicious = vt.get("malicious", 0)
                if malicious >= 5:
                    result["risk_score"] = min(result["risk_score"] + 40, 100)
                    result["findings"].append({
                        "type": "virustotal_malware",
                        "severity": "critical",
                        "description": f"VirusTotal: {malicious} engines detected this APK"
                    })
                elif malicious >= 1:
                    result["risk_score"] = min(result["risk_score"] + 20, 100)
                    result["findings"].append({
                        "type": "virustotal_flagged",
                        "severity": "high",
                        "description": f"VirusTotal: {malicious} engine(s) flagged this APK"
                    })
            
            # BOOST if high entropy (packed/encrypted)
            if result["entropy"] > 7.5:
                result["risk_score"] = min(result["risk_score"] + 10, 100)
                result["findings"].append({
                    "type": "high_entropy",
                    "severity": "medium", 
                    "description": f"High entropy ({result['entropy']}) - may be packed"
                })
                
        except Exception as e:
            logger.error("File scanner failed: %s", e)
    
    # Final risk level
    result["risk_level"] = determine_risk_level(result["risk_score"])
    result["explanation"] = generate_explanation(
        result["risk_level"],
        result["risk_score"],
        len(result["risky_permissions"])
    )
    
    return result