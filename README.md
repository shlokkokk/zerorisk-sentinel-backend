# ZeroRisk Sentinel - Backend

A Python Flask backend that powers ZeroRisk Sentinel's advanced threat detection capabilities. Provides YARA-based malware scanning, VirusTotal integration, URL threat intelligence, and AI-powered analysis explanations.

**Created by Shlok Shah**

---

## Overview

This backend extends the frontend's capabilities with server-side analysis that would be impractical or impossible in a browser. It handles file hashing, YARA rule compilation, external API queries, and LLM-based explanations.

---

## Backend Structure

```
├── server.py           # Flask app with CORS, route handlers
├── file_scanner.py     # YARA rules, entropy, hashes, VirusTotal
├── url_scanner.py      # Multi-source URL threat intelligence
├── apk_analyzer.py     # Android APK permission analysis
├── ai_explainer.py     # Groq API integration for explanations
├── requirements.txt    # Python dependencies
└── start.sh            # Launch script
```

---

## How It Works

### Request Flow

```
Frontend Request
      │
      ▼
┌─────────────┐
│ Flask Server│
└──────┬──────┘
       │
       ├──► File? ──► file_scanner.py
       │               ├── YARA compilation
       │               ├── Hash calculation (MD5, SHA1, SHA256)
       │               ├── Entropy analysis
       │               └── VirusTotal lookup
       │
       ├──► URL? ───► url_scanner.py
       │               ├── Google Safe Browsing
       │               ├── URLHaus
       │               ├── VirusTotal URL
       │               ├── SSL certificate analysis
       │               └── DNS/WHOIS checks
       │
       ├──► APK? ───► apk_analyzer.py
       │               ├── AndroGuard parsing
       │               ├── Permission risk scoring
       │               └── Merged file scanner results
       │
       └──► AI? ────► ai_explainer.py
                       └── Groq API (Llama 3.3 70B)
```

---

## Main Features

### File Scanner (`file_scanner.py`)

| Feature | Description |
|---------|-------------|
| **YARA Rules** | Pattern matching against malware signatures (loads from `yara_rules/` directory) |
| **Entropy Analysis** | Shannon entropy (0-8 scale) to detect packed/encrypted files |
| **Cryptographic Hashes** | MD5, SHA1, SHA256 for reputation lookups |
| **VirusTotal** | Hash-based reputation check against 70+ AV engines |
| **File Type Detection** | Magic number analysis with extension mismatch detection |
| **PE Analysis** | Basic Windows executable structure validation |

### URL Scanner (`url_scanner.py`)

| Feature | Description |
|---------|-------------|
| **Google Safe Browsing** | Real-time phishing/malware URL checks |
| **URLHaus** | Malware distribution URL database |
| **VirusTotal URL** | Multi-engine URL reputation |
| **DNS Analysis** | A/MX/TXT records, SPF detection |
| **SSL Certificate** | Validity, expiry, self-signed detection |
| **Redirect Chain** | Follows up to 5 redirects |
| **Domain Age** | WHOIS-based registration analysis |
| **Heuristics** | IP URLs, shorteners, phishing keywords, risky TLDs |

### APK Analyzer (`apk_analyzer.py`)

- **Permission Analysis**: 12 predefined risk rules (SMS access, accessibility services, device admin, etc.)
- **Risk Scoring**: Weighted scoring (critical=35, high=20, medium=10, low=5)
- **Metadata Extraction**: Package name, version, SDK levels, activities, services
- **Permission Combos**: Detects dangerous permission pairs
- **Merged Intelligence**: Combines with file scanner (hashes, entropy, VirusTotal)

### AI Explainer (`ai_explainer.py`)

- Uses Groq API (Llama 3.3 70B) for natural language summaries
- Graceful fallback to static explanations if AI unavailable
- ~100 word briefings from security analyst perspective
- Explicitly notes static analysis limitations

---

## Detection & Analysis Logic

### Threat Scoring (0-100)

**File Scanner:**
- YARA matches: +15 per match
- High severity findings: +10 each
- Medium severity: +5 each
- Entropy >7.5: +20
- Extension mismatch: +25
- VirusTotal detections: +3 per engine (max 30)

**URL Scanner:**
- Google Safe Browsing hit: +40
- URLHaus listing: +35
- VirusTotal detections: +5 per engine (max 25)
- Raw IP in URL: +30
- URL shortener: +25
- Phishing keywords: +20
- Risky TLD: +20
- No HTTPS: +15

**APK Analyzer:**
- Critical permissions: +35 each
- High permissions: +20 each
- Medium: +10, Low: +5
- Dangerous combos: +15-25 bonus
- VirusTotal boost: +20-40 if flagged

### Severity Levels

| Score | Level |
|-------|-------|
| 0-9 | `safe` |
| 10-29 | `low` |
| 30-59 | `medium` |
| 60-79 | `high` |
| 80-100 | `critical` |

---

## API Endpoints

### Status Check
```
GET /api/status
```
Returns backend health, available features, YARA status, and API key configuration.

### File Scanning
```
POST /api/scan-file
Content-Type: multipart/form-data
Body: file (binary)
```
Returns hashes, entropy, YARA matches, file type, VirusTotal results, threat score.

### Hash Lookup
```
GET /api/scan-hash/<md5|sha1|sha256>
```
Check hash against VirusTotal without uploading file.

### APK Analysis
```
POST /api/analyze-apk
Content-Type: multipart/form-data
Body: file (binary .apk)
```
Returns permissions, risk scoring, metadata, hashes, VirusTotal results.

### URL Analysis
```
POST /api/analyze-url
Content-Type: application/json
Body: { "url": "https://example.com" }
```
Returns threat score, findings, external service results, heuristic analysis.

### AI Explanation
```
POST /api/ai-explain
Content-Type: application/json
Body: {
  "analysis_type": "file|url|apk",
  "target": "filename.exe",
  "threat_score": 85,
  "threat_level": "critical",
  "findings": [...]
}
```
Returns AI-generated natural language summary.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | Flask + Flask-CORS |
| APK Analysis | androguard |
| Malware Signatures | yara-python |
| File Type Detection | python-magic (libmagic) |
| DNS Resolution | dnspython |
| WHOIS Lookup | python-whois |
| AI Service | Groq API (Llama 3.3 70B) |
| External APIs | VirusTotal, Google Safe Browsing, URLHaus |

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `GROQ_API_KEY` | AI explanations (starts with `gsk_`) |
| `VIRUSTOTAL_API_KEY` | File/URL reputation checks |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Phishing/malware URL detection |
| `PORT` | Server port (default: 5000) |

---

## Deployment Notes

### Production Considerations

- **File Size Limit**: 100MB max upload
- **Temp Files**: Automatically cleaned up after each scan
- **Timeouts**: URL scanning has 15s overall timeout; individual services 5-10s
- **CORS**: Currently allows all origins (`*`) - restrict for production
- **No Authentication**: Add API key validation if exposing publicly
- **Rate Limiting**: Consider Flask-Limiter for abuse prevention

---

## Limitations

1. **Static Analysis Only** – No dynamic execution or sandboxing
2. **YARA Dependency** – Effectiveness depends on rule quality
3. **API Rate Limits** – VirusTotal (4/min free), Groq (varies by plan)
4. **APK Analysis** – AndroGuard may struggle with heavily obfuscated APKs
5. **No Persistence** – Scan results not stored; stateless design

---

## Possible Improvements

- Dynamic analysis integration (Any.Run, Hybrid Analysis)
- Redis caching for VirusTotal results
- Celery/RQ for async processing with webhooks
- Automated YARA rule updates
- ML models for unknown malware detection
- Certificate Transparency log monitoring
- API key management and usage quotas
- Prometheus/Grafana metrics

---

**© ZeroRisk Sentinel - Shlok Shah**
