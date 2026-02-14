<div align="center">

<img src="https://img.shields.io/badge/ZeroRisk-Sentinel-00d4ff?style=for-the-badge&logo=shield&logoColor=white" alt="ZeroRisk Sentinel">

### 🔒 Backend Intelligence Engine

<img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/Flask-2.0+-000000?style=flat-square&logo=flask&logoColor=white">
<img src="https://img.shields.io/badge/YARA-4.2+-1f4e79?style=flat-square">
<img src="https://img.shields.io/badge/Groq-AI-FF6B6B?style=flat-square">

**Multi-layered threat detection powered by Python**

[Overview](#overview) • [Architecture](#architecture) • [Capabilities](#capabilities) • [API Reference](#api-reference)

</div>

---

## Overview

This is the backend intelligence engine for ZeroRisk Sentinel - a cybersecurity analysis platform I built to detect threats across files, URLs, and Android applications. The backend provides enhanced threat intelligence through YARA rule scanning, VirusTotal integration, AI-powered explanations, and live sandbox analysis.

The system follows a hybrid architecture where client-side JavaScript performs initial triage, and this Python backend provides deep analysis when available.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZeroRisk Sentinel Backend                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   server.py  │  │ ai_explainer │  │file_scanner  │           │
│  │   (Flask)    │  │   (Groq)     │  │  (YARA/VT)   │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                 │                   │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────────┐       │
│  │apk_analyzer  │  │url_scanner   │  │sandbox_scanner   │       │
│  │(AndroGuard)  │  │(Multi-API)   │  │(Hybrid Analysis) │       │
│  └──────────────┘  └──────────────┘  └──────────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Capabilities

### 🛡️ File Analysis Engine (`file_scanner.py`)

| Feature | Description |
|---------|-------------|
| **YARA Rules** | Pattern-based malware detection with custom rule support |
| **Entropy Analysis** | Detect packed/encrypted files (0-8 scale) |
| **File Hashing** | MD5, SHA1, SHA256 generation |
| **VirusTotal** | Hash lookup against 70+ antivirus engines |
| **Magic Numbers** | Real file type detection vs claimed extension |
| **PE Analysis** | Windows executable structure inspection |

```python
# Example: Scan a file
from file_scanner import scan_file

result = scan_file("/path/to/file.exe", "file.exe")
print(f"Threat Level: {result['threat_level']}")
print(f"VirusTotal: {result['virustotal']['malicious']}/70 flagged")
```

---

### 🔗 URL Security Scanner (`url_scanner.py`)

| Source | Purpose |
|--------|---------|
| **Google Safe Browsing** | Known malicious URL database |
| **URLHaus** | Community-driven malware URLs |
| **VirusTotal URL** | 70+ vendor URL scanning |
| **SSL Analysis** | Certificate validation & expiry |
| **DNS Records** | A, MX, TXT (SPF) lookup |
| **Redirect Chain** | Follow up to 5 hops |
| **WHOIS** | Domain age & registration |

**Deep Scan Mode:** Live browser sandboxing via urlscan.io
- Screenshot capture
- Network activity monitoring
- Brand impersonation detection
- Console log collection

---

### 📱 APK Inspector (`apk_analyzer.py`)

Analyzes Android APK permissions using a curated rule set:

| Permission | Severity | Risk |
|------------|----------|------|
| `BIND_ACCESSIBILITY_SERVICE` | 🔴 Critical | UI observation, keylogging |
| `READ_SMS` / `RECEIVE_SMS` | 🔴 Critical | OTP interception |
| `SYSTEM_ALERT_WINDOW` | 🟠 High | Clickjacking, phishing overlays |
| `BIND_VPN_SERVICE` | 🟠 High | Traffic interception |
| `MANAGE_EXTERNAL_STORAGE` | 🟠 High | Data theft, ransomware |

Merged analysis includes:
- File hashes & entropy
- VirusTotal APK lookup
- Permission combination heuristics

---

### 🤖 AI Explanations (`ai_explainer.py`)

Powered by **Groq API** using Llama 3.3 70B:

```python
from ai_explainer import explain_with_ai

data = {
    "analysis_type": "file_scan",
    "target": "suspicious.exe",
    "threat_score": 85,
    "threat_level": "critical",
    "findings": ["keylogger_pattern", "network_exfiltration"]
}

explanation = explain_with_ai(data)
# Returns human-readable threat analysis
```

**Features:**
- Context-aware threat explanations
- Identifies critical indicators
- Explains code capabilities
- Suggests verification steps
- Graceful fallback to heuristic mode

---

### 🧪 File Sandbox (`sandbox_scanner.py`)

Integration with **Hybrid Analysis** for real-time execution:

| Capability | Description |
|------------|-------------|
| **Isolated Execution** | Windows 7 32-bit VM environment |
| **Process Monitoring** | Detects process injection/hollowing |
| **Network Tracking** | Captures all outbound connections |
| **File Drops** | Identifies payload delivery |
| **MITRE ATT&CK** | Maps techniques to framework |
| **Screenshots** | Visual capture of execution |

---

## API Reference

### Status Check
```http
GET /api/status
```

### File Operations
```http
POST /api/scan-file          # Standard file scan
POST /api/scan-file-deep     # File scan + sandbox submission
GET  /api/scan-hash/<hash>   # Hash-only VirusTotal lookup
```

### URL Operations
```http
POST /api/analyze-url        # Multi-source URL analysis
POST /api/urlscan/submit     # Submit to urlscan.io sandbox
GET  /api/urlscan/result/<id> # Poll for sandbox results
```

### APK Analysis
```http
POST /api/analyze-apk        # Permission + file intelligence
```

### Sandbox
```http
POST /api/sandbox/submit     # Submit file to Hybrid Analysis
GET  /api/sandbox/result/<job_id>  # Poll sandbox results
```

### AI Explanations
```http
POST /api/ai-explain         # Generate AI threat analysis
```

---

## Environment Variables

```bash
# Required for core functionality
GROQ_API_KEY=gsk_xxxxxxxx    # AI explanations

# Enhanced threat intelligence
VIRUSTOTAL_API_KEY=vt_xxx    # Hash & URL lookups
HYBRID_ANALYSIS_API_KEY=ha_  # File sandbox
URLSCAN_API_KEY=usc_xxx      # URL sandbox

# Optional
GOOGLE_SAFE_BROWSING_API_KEY=gsb_xxx
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | Flask |
| Malware Signatures | YARA |
| APK Parsing | AndroGuard |
| File Type Detection | python-magic |
| DNS Resolution | dnspython |
| WHOIS Lookup | python-whois |
| AI/ML | Groq API (Llama 3.3 70B) |

---

## Response Format

All endpoints return standardized responses:

```json
{
  "success": true,
  "data": {
    "threat_level": "high",
    "threat_score": 75,
    "findings": [...],
    "backend_based": true
  }
}
```

---

<div align="center">

**Built with precision by Shlok Shah**

<img src="https://img.shields.io/badge/Threat-Intelligence-00d4ff?style=flat-square"> <img src="https://img.shields.io/badge/Malware-Analysis-ff6b35?style=flat-square"> <img src="https://img.shields.io/badge/Security-First-00ff41?style=flat-square">

</div>
