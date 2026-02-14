"""
ZeroRisk Sentinel - File Sandbox Scanner
Hybrid Analysis integration for deep file scanning
Returns results in the same format as file_scanner.py for consistency
"""

import os
import logging
import requests
from typing import Dict, Any, List
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "")


class HybridAnalysisScanner:
    """
    Hybrid Analysis sandbox scanner for deep file analysis.
    Free tier: 100 requests/day, 5 requests/minute
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "api-key": HYBRID_ANALYSIS_API_KEY,
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json"
        })

        self.base_url = "https://www.hybrid-analysis.com/api/v2"
    
    def submit_file(self, filepath: str, filename: str) -> Dict[str, Any]:
        """
        Submit file to Hybrid Analysis sandbox for analysis.
        
        Args:
            filepath: Path to the file on disk
            filename: Original filename
            
        Returns:
            Dict with success status and job_id for polling
        """
        if not HYBRID_ANALYSIS_API_KEY:
            logger.warning("[HYBRID] API key not configured")
            return {
                "success": False,
                "error": "HYBRID_ANALYSIS_API_KEY not configured",
                "note": "Get free API key from https://www.hybrid-analysis.com"
            }
        
        try:
            # Read file and submit using multipart form data
            with open(filepath, "rb") as f:
                files = {"file": (filename, f, "application/octet-stream")}
                data = {
                    "environment_id": "100",  # Windows 7 32-bit
                    "experimental_anti_evasion": "true",
                    "script_logging": "true",
                    "input_sample_tampering": "true"
                }
                
                logger.info(f"[HYBRID] Submitting {filename} to {self.base_url}/submit/file")
                
                response = self.session.post(
                    f"{self.base_url}/submit/file",
                    files=files,
                    data=data,
                    timeout=60
                )
            
            logger.info(f"[HYBRID] Response status: {response.status_code}")
            
            if response.status_code == 429:
                return {
                    "success": False,
                    "error": "Rate limit exceeded. Free tier: 5 requests/minute, 100/day",
                    "rate_limited": True
                }
            
            if response.status_code == 401:
                return {
                    "success": False,
                    "error": "Invalid API key. Check your HYBRID_ANALYSIS_API_KEY"
                }
            
            if response.status_code == 400:
                try:
                    data = response.json()
                    return {
                        "success": False,
                        "error": data.get("message", "Bad request")
                    }
                except:
                    return {
                        "success": False,
                        "error": f"Bad request: {response.text[:200]}"
                    }
            
            response.raise_for_status()
            data = response.json()
            
            logger.info(f"[HYBRID] Submitted {filename}, job_id: {data.get('job_id')}")
            
            return {
                "success": True,
                "job_id": data.get("job_id"),
                "sha256": data.get("sha256"),
                "submission_id": data.get("submission_id"),
                "message": "File submitted to sandbox successfully"
            }
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"[HYBRID] HTTP error: {e}")
            return {"success": False, "error": f"HTTP error: {str(e)}"}
        except Exception as e:
            logger.error(f"[HYBRID] Submit error: {e}")
            return {"success": False, "error": str(e)}
    
    def get_report(self, job_id: str) -> Dict[str, Any]:
        """
        Poll Hybrid Analysis for scan results.
        
        Args:
            job_id: The job ID returned from submit_file
            
        Returns:
            Dict with status and parsed results (same format as file_scanner.py)
        """
        try:
            response = self.session.get(
                f"{self.base_url}/report/{job_id}/summary",
                timeout=15
            )
            
            if response.status_code == 404:
                return {
                    "success": True,
                    "status": "pending",
                    "message": "Analysis still in progress"
                }
            
            response.raise_for_status()
            data = response.json()
            
            # Check if still processing
            if data.get("state") == "IN_PROGRESS":
                return {
                    "success": True,
                    "status": "pending",
                    "message": "Sandbox analysis in progress"
                }
            
            # Parse completed report
            parsed = self._parse_report(data, job_id)
            parsed["success"] = True
            parsed["status"] = "completed"
            
            return parsed
            
        except requests.exceptions.Timeout:
            return {
                "success": True,
                "status": "pending",
                "message": "Request timed out, will retry"
            }
        except Exception as e:
            logger.error(f"[HYBRID] Report error: {e}")
            return {
                "success": True,
                "status": "pending",
                "message": "Error fetching result, will retry"
            }
    
    def _parse_report(self, data: Dict, job_id: str) -> Dict[str, Any]:
        """
        Parse Hybrid Analysis report into ZeroRisk Sentinel format.
        
        Returns dict matching file_scanner.py output format:
        {
            filename: str,
            size: int,
            hashes: {md5, sha1, sha256},
            file_type: {description, mime},
            entropy: float,
            entropy_analysis: {...},
            findings: [...],
            virustotal: {...} or None,
            threat_score: int (0-100),
            threat_level: str ('safe', 'low', 'medium', 'high', 'critical'),
            scan_time: str (ISO format),
            sandbox_data: {...}  # Additional sandbox-specific data
        }
        """
        logger.info(f"[HYBRID] Parsing report for job {job_id}")
        
        # Extract core data
        verdict = data.get("verdict", "unknown")
        threat_score_ha = data.get("threat_score", 0)  # 0-10 scale from HA
        threat_level_ha = data.get("threat_level", 0)  # 0-10 scale from HA
        
        # Convert HA threat level (0-10) to our threat level
        threat_level = self._convert_threat_level(verdict, threat_level_ha)
        
        # Convert HA threat score (0-10) to our scale (0-100)
        threat_score = min(threat_score_ha * 10, 100)
        
        # Build findings list
        findings = self._extract_findings(data)
        
        # Extract file hashes
        hashes = {
            "md5": data.get("md5", "unknown"),
            "sha1": data.get("sha1", "unknown"),
            "sha256": data.get("sha256", "unknown")
        }
        
        # Extract file info
        file_type = {
            "description": data.get("type", "Unknown"),
            "mime": data.get("type_short", "application/octet-stream")
        }
        
        # Build sandbox data object
        sandbox_data = {
            "job_id": job_id,
            "report_url": f"https://www.hybrid-analysis.com/sample/{data.get('sha256', '')}",
            "verdict": verdict,
            "threat_score_ha": threat_score_ha,
            "threat_level_ha": threat_level_ha,
            "analysis_time": data.get("analysis_time", 0),
            "environment": data.get("environment_description", "Unknown"),
            "environment_id": data.get("environment_id", "100"),
            "processes_spawned": len(data.get("processes", [])),
            "network_connections": len(data.get("hosts", [])),
            "domains_contacted": data.get("domains", []),
            "ips_contacted": data.get("ips", []),
            "mitre_techniques": [m.get("technique") for m in data.get("mitre_attcks", [])],
            "tags": data.get("tags", []),
            "signatures": data.get("signatures", []),
            "screenshots_count": len(data.get("screenshots", [])),
            "extracted_files_count": len(data.get("extracted_files", [])),
            "submitted_at": data.get("submit_name", ""),
            "file_size": data.get("size", 0),
            "compiler": data.get("compiler", "Unknown"),
            "packer": data.get("packer", "None")
        }
        
        # Generate explanation
        explanation = self._generate_explanation(verdict, threat_level_ha, findings, sandbox_data)
        
        return {
            "filename": data.get("submit_name", "unknown"),
            "size": data.get("size", 0),
            "hashes": hashes,
            "file_type": file_type,
            "entropy": 0.0,  # Sandbox doesn't provide entropy
            "entropy_analysis": {
                "value": 0.0,
                "interpretation": "Entropy analysis not available from sandbox"
            },
            "findings": findings,
            "virustotal": None,  # Will be merged from regular scan
            "threat_score": threat_score,
            "threat_level": threat_level,
            "scan_time": datetime.utcnow().isoformat(),
            "explanation": explanation,
            "backend_based": True,
            "deep_scan": True,
            "sandbox_data": sandbox_data
        }
    
    def _convert_threat_level(self, verdict: str, threat_level_ha: int) -> str:
        """
        Convert Hybrid Analysis verdict and threat level to our threat levels.
        
        HA verdicts: malicious, suspicious, no_specific_threat, unknown
        HA threat_level: 0-10 scale
        """
        if verdict == "malicious" or threat_level_ha >= 5:
            return "critical"
        elif verdict == "suspicious" or threat_level_ha >= 3:
            return "high"
        elif threat_level_ha >= 2:
            return "medium"
        elif threat_level_ha >= 1:
            return "low"
        else:
            return "safe"
    
    def _extract_findings(self, data: Dict) -> List[Dict]:
        """
        Extract security findings from Hybrid Analysis report.
        Returns list of finding dicts with type, severity, description.
        """
        findings = []
        
        # MITRE ATT&CK techniques
        mitre_techniques = data.get("mitre_attcks", [])
        for technique in mitre_techniques:
            findings.append({
                "type": "mitre_attack",
                "severity": "high",
                "description": f"MITRE ATT&CK {technique.get('attck_id', '')}: {technique.get('technique', 'Unknown technique')}",
                "technique": technique.get("technique"),
                "attck_id": technique.get("attck_id"),
                "tactic": technique.get("tactic")
            })
        
        # Sandbox signatures/tags
        tags = data.get("tags", [])
        for tag in tags:
            if isinstance(tag, str):
                findings.append({
                    "type": "sandbox_signature",
                    "severity": "medium",
                    "description": f"Sandbox signature: {tag}"
                })
        
        # Process analysis
        processes = data.get("processes", [])
        if len(processes) > 5:
            findings.append({
                "type": "process_injection",
                "severity": "high",
                "description": f"Spawned {len(processes)} processes during execution, possible process injection or hollowing",
                "process_count": len(processes)
            })
        elif len(processes) > 2:
            findings.append({
                "type": "multiple_processes",
                "severity": "medium",
                "description": f"Spawned {len(processes)} processes during execution",
                "process_count": len(processes)
            })
        
        # Network activity
        hosts = data.get("hosts", [])
        domains = data.get("domains", [])
        
        if hosts:
            suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".icu", ".cyou"]
            suspicious_hosts = [
                h for h in hosts 
                if any(str(h).lower().endswith(tld) for tld in suspicious_tlds)
            ]
            
            if suspicious_hosts:
                findings.append({
                    "type": "suspicious_network",
                    "severity": "high",
                    "description": f"Connected to {len(suspicious_hosts)} suspicious domains during execution",
                    "domains": suspicious_hosts[:5]
                })
            else:
                findings.append({
                    "type": "network_activity",
                    "severity": "low",
                    "description": f"Made {len(hosts)} network connections during execution",
                    "connection_count": len(hosts)
                })
        
        # Dropped/extracted files
        extracted = data.get("extracted_files", [])
        if len(extracted) > 3:
            findings.append({
                "type": "dropped_files",
                "severity": "high",
                "description": f"Dropped {len(extracted)} files during execution, possible payload delivery",
                "file_count": len(extracted)
            })
        elif extracted:
            findings.append({
                "type": "dropped_files",
                "severity": "medium",
                "description": f"Dropped {len(extracted)} file(s) during execution",
                "file_count": len(extracted)
            })
        
        # Registry modifications
        regkeys = data.get("regkey_count", 0)
        if regkeys > 10:
            findings.append({
                "type": "registry_modification",
                "severity": "medium",
                "description": f"Modified {regkeys} registry keys, possible persistence mechanism",
                "registry_count": regkeys
            })
        
        # Anti-analysis / evasion
        if data.get("anti_analysis", False):
            findings.append({
                "type": "anti_analysis",
                "severity": "high",
                "description": "Detected anti-analysis or anti-sandbox techniques"
            })
        
        # Known packer
        packer = data.get("packer", "")
        if packer and packer != "None":
            findings.append({
                "type": "packed_binary",
                "severity": "medium",
                "description": f"Binary packed with: {packer}",
                "packer": packer
            })
        
        return findings
    
    def _generate_explanation(self, verdict: str, threat_level: int, 
                              findings: List[Dict], sandbox_data: Dict) -> str:
        """Generate human-readable security assessment."""
        parts = []
        
        # Verdict summary
        if verdict == "malicious":
            parts.append("CRITICAL: Sandbox analysis detected MALICIOUS behavior during execution.")
        elif verdict == "suspicious":
            parts.append("WARNING: Suspicious behavior patterns observed during sandboxed execution.")
        elif verdict == "no_specific_threat":
            parts.append("SAFE: No specific threats detected during sandbox analysis.")
        else:
            parts.append(f"INFO: Sandbox verdict: {verdict}")
        
        # Technical details
        parts.append(f"\nSandbox Analysis Details:")
        parts.append(f"- Threat Level: {threat_level}/10")
        parts.append(f"- Processes Spawned: {sandbox_data['processes_spawned']}")
        parts.append(f"- Network Connections: {sandbox_data['network_connections']}")
        parts.append(f"- Environment: {sandbox_data['environment']}")
        parts.append(f"- Analysis Duration: {sandbox_data['analysis_time']} seconds")
        
        # Findings summary
        if findings:
            critical = len([f for f in findings if f["severity"] == "critical"])
            high = len([f for f in findings if f["severity"] == "high"])
            medium = len([f for f in findings if f["severity"] == "medium"])
            parts.append(f"\nSecurity Indicators: {len(findings)} total")
            if critical:
                parts.append(f"- Critical: {critical}")
            if high:
                parts.append(f"- High: {high}")
            if medium:
                parts.append(f"- Medium: {medium}")
        
        # MITRE techniques
        if sandbox_data["mitre_techniques"]:
            techniques = ", ".join(sandbox_data["mitre_techniques"][:3])
            parts.append(f"\nMITRE ATT&CK Techniques Detected: {techniques}")
        
        # Report link
        parts.append(f"\nFull Report: {sandbox_data['report_url']}")
        
        return "\n".join(parts)


def submit_to_sandbox(filepath: str, filename: str) -> Dict[str, Any]:
    """Submit file to Hybrid Analysis sandbox."""
    scanner = HybridAnalysisScanner()
    return scanner.submit_file(filepath, filename)


def get_sandbox_result(job_id: str) -> Dict[str, Any]:
    """Get Hybrid Analysis sandbox result."""
    scanner = HybridAnalysisScanner()
    return scanner.get_report(job_id)