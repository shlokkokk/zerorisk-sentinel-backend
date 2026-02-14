# ZeroRisk Sentinel Backend

A comprehensive cybersecurity analysis API built with Flask, integrating multiple threat intelligence engines, static analysis tools, and AI-powered security explanations. This backend powers ZeroRisk Sentinel's file scanning, APK analysis, URL assessment, and sandbox detonation capabilities.

**Developed by Shlok Shah**

---

## Project Overview

This backend serves as the intelligence layer for ZeroRisk Sentinel, providing enterprise-grade malware detection and threat analysis through a RESTful API. The system combines static analysis techniques with third-party threat intelligence feeds to deliver comprehensive security assessments.

The architecture implements a multi-layered detection approach, utilizing YARA signature matching, entropy analysis, file type verification, hash-based reputation lookups, and optional behavioral analysis through cloud sandboxing. An AI explanation engine synthesizes findings into actionable security insights.

---

## System Architecture

### Technology Stack

| Component | Implementation |
|-----------|----------------|
| **Web Framework** | Flask 3.x with CORS middleware |
| **Malware Detection** | YARA rules engine, python-magic file typing |
| **Threat Intel APIs** | VirusTotal, Google Safe Browsing, URLhaus, urlscan.io |
| **Sandbox Integration** | Hybrid Analysis API for behavioral detonation |
| **AI Processing** | Groq API with llama-3.3-70b-versatile model |
| **APK Analysis** | androguard for Android package parsing |
| **Network Analysis** | dnspython for DNS resolution, python-whois |

### Project Structure

```
zerorisk-sentinel-backend/
├── server.py               # Flask API server with endpoint definitions
├── file_scanner.py         # File malware detection engine
├── apk_analyzer.py         # Android package security analysis
├── url_scanner.py          # URL threat assessment system
├── sandbox_scanner.py      # Hybrid Analysis integration layer
├── ai_explainer.py         # Groq-powered security explanations
├── requirements.txt        # Python dependency specifications
├── yara_rules/            # YARA malware signature database
│   ├── ransomware.yar
│   ├── trojans.yar
│   ├── keylogger.yar
│   ├── packers.yar
│   └── android_malware_apk.yar
└── README.md
```

---

## Core Capabilities

### File Malware Scanning

The file scanner implements multi-layered static analysis combining signature-based detection with heuristic analysis:

**Detection Methods:**
- YARA rule matching against custom malware signatures
- Shannon entropy calculation for packer/encryption detection
- File type verification via magic number analysis
- Extension spoofing detection
- Cryptographic hash generation (MD5, SHA1, SHA256)
- VirusTotal hash reputation lookup

**YARA Rule Categories:**
- Ransomware encryption patterns
- Trojan backdoor signatures
- Keylogger surveillance indicators
- Executable packer detection
- Android-specific malware patterns

**Entropy Analysis Thresholds:**
```
0.0-3.0: Plain text, uncompressed data
3.0-5.0: Structured code, configuration files
5.0-7.0: Compressed archives, multimedia
7.0-8.0: Encrypted/packed executables (high risk)
```

### APK Security Analysis

Android package analysis extracts permissions, metadata, and components to calculate risk scores:

**Analysis Components:**
- Permission enumeration and risk classification
- Package manifest parsing
- Component cataloging (activities, services, broadcast receivers)
- Dangerous permission combination detection
- File hash-based reputation checking
- Entropy analysis for packed payloads

**Risk Scoring Algorithm:**
```python
Critical permissions: +35 points
High risk permissions: +20 points
Medium risk: +10 points
Low risk: +5 points
Dangerous combinations: +15-25 points
VirusTotal detections: +20-40 points
High entropy packing: +10 points
```

### URL Threat Assessment

Multi-source URL analysis combining reputation databases with heuristic checks:

**Integrated Services:**
- Google Safe Browsing threat database
- URLhaus malware URL tracker
- VirusTotal URL reputation
- DNS record analysis (A, MX, SPF records)
- SSL certificate validation
- HTTP redirect chain analysis
- WHOIS domain age lookup

**Heuristic Detection:**
- IP address-based URLs
- URL shortening service detection
- Phishing keyword patterns
- High-risk TLD identification
- Excessive path length analysis

### Sandbox Behavioral Analysis

Integration with Hybrid Analysis cloud sandbox for runtime detonation:

**Behavioral Monitoring:**
- Process creation and injection detection
- Network communication analysis
- File system modification tracking
- Registry manipulation logging
- MITRE ATT&CK technique mapping
- Anti-analysis evasion detection

**Supported Environments:**
- Windows 7/10/11 (32-bit and 64-bit architectures)
- Android emulator environments
- Configurable analysis duration and VM selection

### AI-Powered Explanations

Natural language security summaries generated via Groq API:

**Capabilities:**
- Contextual threat analysis
- Critical indicator prioritization
- Evidence-based risk assessment
- Actionable remediation recommendations
- Static analysis limitation disclosure

**Prompt Engineering:**
The system employs specialized prompts that enforce analytical rigor, requiring the AI to distinguish between observed indicators and speculative conclusions while maintaining professional security analyst tone.

---

## API Endpoints

### Status Health Check

```http
GET /api/status
```

Returns service availability and feature configuration status.

### File Analysis

```http
POST /api/scan-file
Content-Type: multipart/form-data
```

Executes comprehensive static analysis on uploaded files, returning hashes, YARA matches, entropy metrics, file type verification, and VirusTotal results.

### Deep File Scan

```http
POST /api/scan-file-deep
Content-Type: multipart/form-data
```

Combines standard static analysis with sandbox submission, returning immediate static results plus a job ID for behavioral analysis polling.

### Sandbox Result Retrieval

```http
GET /api/sandbox/result/<job_id>
```

Polls Hybrid Analysis for completed behavioral analysis results, including process trees, network activity, and MITRE ATT&CK mappings.

### Hash Lookup

```http
GET /api/scan-hash/<hash>
```

Queries VirusTotal reputation database using file hash (MD5/SHA1/SHA256) without file upload.

### APK Analysis

```http
POST /api/analyze-apk
Content-Type: multipart/form-data
```

Analyzes Android packages for permission risks, component enumeration, and combined file/permission scoring.

### URL Scanning

```http
POST /api/analyze-url
Content-Type: application/json
```

Checks URL reputation across multiple threat intelligence sources with DNS and SSL analysis.

### URL Sandbox Detonation

```http
POST /api/urlscan/submit
GET /api/urlscan/result/<scan_id>
```

Submits URLs to browser-based sandbox for screenshot capture, network analysis, and phishing detection.

### AI Explanation Generation

```http
POST /api/ai-explain
Content-Type: application/json
```

Generates natural language security analysis from scan results using Groq AI.

---

## Technical Implementation Details

### File Scanner Module

**Key Functions:**
- `calculate_hashes()`: Computes MD5, SHA1, SHA256 using streaming to handle large files
- `calculate_entropy()`: Shannon entropy calculation on first 1MB of file data
- `detect_file_type()`: Magic number-based file type identification with fallback
- `scan_with_yara()`: Parallel YARA rule matching with metadata extraction
- `check_virustotal()`: Hash-based reputation lookup with 10-second timeout
- `check_extension_mismatch()`: Extension spoofing detection via type comparison

**YARA Integration:**
Rules are compiled at server initialization from the `yara_rules/` directory, with automatic namespace assignment per file. Match results include rule name, namespace, tags, and metadata for severity classification.

**Entropy Interpretation:**
Values above 7.0 trigger high-risk findings, as legitimate executables typically exhibit entropy between 5.0-7.0. Encrypted ransomware and packed malware often exceed 7.5.

### APK Analyzer Module

**Permission Risk Classification:**
Implemented via regex pattern matching against permission strings:

```python
PERMISSION_RULES = [
    {
        "pattern": r"^android\.permission\.READ_SMS$",
        "severity": "critical",
        "reason": "Access to SMS may intercept OTPs"
    },
    # ... additional rules
]
```

**Combination Heuristics:**
Specific permission combinations boost risk scores:
- BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW → +25 points
- RECEIVE_BOOT_COMPLETED + INTERNET → +15 points

These patterns indicate potential overlay attacks or persistent malware.

### URL Scanner Module

**Service Integration Pattern:**
Each threat intelligence service is wrapped in a try-except block with timeout enforcement, allowing graceful degradation when services are unavailable.

**DNS Analysis:**
The system queries A, MX, and TXT records to detect:
- Newly registered domains (DNS propagation issues)
- Missing mail infrastructure (potential phishing)
- Lack of SPF records (spoofing vulnerability)

**Redirect Chain Analysis:**
Follows up to 5 HTTP redirects, detecting:
- Open redirect exploitation
- Malicious short URL resolution
- Territorial redirects to geo-specific threats

### Sandbox Scanner Module

**Submission Workflow:**
1. File uploaded to temporary storage with UUID naming
2. Multipart form data constructed with environment ID
3. Hybrid Analysis API returns job_id for polling
4. Temporary file deleted immediately after submission

**Result Parsing:**
The `_parse_report()` function normalizes Hybrid Analysis JSON into ZeroRisk Sentinel's standard schema, mapping their 0-10 threat scale to 0-100 scoring.

**MITRE ATT&CK Extraction:**
Detected techniques are extracted from the `mitre_attcks` array and cross-referenced with severity classifications to boost threat scores appropriately.

### AI Explainer Module

**Prompt Construction:**
The `_build_prompt()` function formats scan results into structured context for the AI, explicitly instructing the model to:
- Prioritize critical indicators
- Acknowledge static analysis limitations
- Avoid generic disclaimers
- Provide actionable insights

**Fallback Mechanism:**
When Groq API is unavailable, the system returns a structured fallback object with error details, allowing the frontend to display heuristic results instead.

---

## Security Analysis Workflow

### Standard File Scan Flow

```
File Upload → Temporary Storage
     ↓
Hash Calculation (MD5/SHA1/SHA256)
     ↓
File Type Detection (magic numbers)
     ↓
Extension Spoofing Check
     ↓
Entropy Analysis (first 1MB)
     ↓
YARA Rule Matching (all rules)
     ↓
VirusTotal Hash Lookup
     ↓
Threat Score Aggregation
     ↓
Response Generation → Cleanup
```

### Deep Scan Flow

```
File Upload → Standard Scan (parallel)
     ↓                    ↓
Immediate Results    Sandbox Submit
     ↓                    ↓
Return job_id        Hybrid Analysis
     ↓                    ↓
Frontend Polling ← Result Ready
     ↓
Behavioral Data Merge → Final Report
```

### URL Analysis Flow

```
URL Input → Basic Validation
     ↓
Parallel Queries:
  - Google Safe Browsing
  - URLhaus Database
  - VirusTotal URL
  - DNS Resolution
  - WHOIS Lookup
  - SSL Certificate Check
  - Redirect Chain Analysis
     ↓
Heuristic Pattern Matching
     ↓
Score Aggregation → Response
```

---

## Performance Characteristics

### Rate Limit Handling

The system implements graceful degradation when API quotas are exhausted:

| Service | Free Tier Limit | Handling Strategy |
|---------|----------------|-------------------|
| VirusTotal | 500 req/day | Returns null, scan continues |
| Groq AI | 30 req/min | Fallback to static explanation |
| Hybrid Analysis | 100 submissions/day | Error message with quota info |
| urlscan.io | Limited scans | Queueing recommendation |
| Google Safe Browsing | 10,000 queries/day | Primary service, rarely limited |

### Timeout Configuration

All external API calls enforce strict timeouts to prevent request hanging:
- VirusTotal: 10 seconds
- Groq AI: 30 seconds
- Hybrid Analysis: 15 seconds
- URL services: 15 seconds
- DNS queries: 5 seconds

### File Size Limits

```python
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB
```

Larger files are rejected with HTTP 413 to prevent memory exhaustion.

---

## Error Handling Strategy

The codebase implements comprehensive exception handling:

**Logging Levels:**
- `INFO`: Successful operations, scan completions
- `WARNING`: API unavailability, missing configuration
- `ERROR`: API failures, YARA compilation errors

**Fallback Chains:**
1. python-magic file detection → basic header detection
2. YARA scanning → built-in pattern matching
3. VirusTotal lookup → entropy-only assessment
4. Groq AI → static heuristic explanation

**Client Error Responses:**
All endpoints return structured JSON with `success` boolean and `error` messages, enabling frontend graceful degradation.

---

## Configuration Requirements

The system expects environment variables for external service authentication:

```
VIRUSTOTAL_API_KEY
GROQ_API_KEY
GROQ_MODEL
GOOGLE_SAFE_BROWSING_API_KEY
URLSCAN_API_KEY
HYBRID_ANALYSIS_API_KEY
```

Missing keys trigger warning logs and disable corresponding features, but the server remains operational with reduced capabilities.

---

## Development Insights

### Design Decisions

**Why Flask over FastAPI:**
Flask was chosen for its mature ecosystem and synchronous request model, which simplifies integration with blocking I/O operations like file scanning and API calls.

**YARA Rule Organization:**
Rules are categorized by threat type in separate files to enable selective loading and easier maintenance. Each rule file represents a threat category namespace.

**Entropy as Primary Heuristic:**
Shannon entropy provides a reliable packed/encrypted executable indicator without requiring execution. Values above 7.0 correlate strongly with malicious intent.

**Sandbox Optional Design:**
Behavioral analysis requires significant time (20-120 seconds) and quota consumption. The two-tier approach (quick static + optional deep) balances speed with thoroughness.

**AI Explanation Integration:**
Natural language summaries bridge the gap between technical findings and user comprehension, making threat assessments accessible to non-security professionals.

### Challenges Addressed

**API Rate Limiting:**
Implemented per-service tracking recommendations (not enforced server-side) and graceful degradation to maintain functionality under quota constraints.

**YARA Compilation Errors:**
Rule syntax errors could crash the server. Wrapped compilation in try-except with per-file error reporting, allowing partial rule loading.

**Large File Memory Issues:**
Streaming hash calculation and chunked entropy analysis prevent memory exhaustion when processing 100MB files.

**Sandbox Polling Complexity:**
Hybrid Analysis requires polling with exponential backoff. The job_id return allows frontend control over polling frequency.

---

## Known Limitations

- **Static Analysis Scope**: Cannot detect runtime polymorphism or VM-aware malware
- **YARA Signature Lag**: New malware families evade signatures until rules are updated
- **API Dependency**: Requires internet connectivity for threat intelligence
- **Heuristic False Positives**: Legitimate packed software triggers encryption warnings
- **Sandbox Quota**: Free tier limits deep scans to ~3-5 per day per key
- **Hash Lookup Privacy**: VirusTotal queries may leak file metadata

---

## Future Architecture Considerations

Technical debt and potential enhancements identified:

- Implement Redis caching layer for VirusTotal hash lookups
- Add WebSocket support for real-time scan progress streaming
- Integrate machine learning model for zero-day detection
- Implement asynchronous task queue (Celery) for sandbox submissions
- Add MongoDB for scan history and analytics
- Create Docker containerization for simplified deployment
- Implement API key rotation and secret management integration
- Add Prometheus metrics exporter for monitoring

---

**Developed by Shlok Shah**
