"""
ZeroRisk Sentinel - Real File Malware Scanner
Adds YARA rules, entropy analysis, file hashing, and VirusTotal integration
"""

import os
import hashlib
import math
import logging
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# Try to import YARA, fallback to built-in if not available
try:
    import yara
    YARA_AVAILABLE = True
    logger.info("[YARA] Successfully imported")
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("[YARA] Not available - using built-in patterns only")

# Try to import python-magic for file type detection
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logger.warning("[MAGIC] python-magic not available - using basic detection")


class FileScanner:
    """Main file scanner with YARA, entropy, and hash analysis"""
    
    def __init__(self):
        self.yara_rules = self._load_yara_rules()
        
    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Load YARA rules from yara_rules directory"""
        if not YARA_AVAILABLE:
            return None
            
        rules_dir = os.path.join(os.path.dirname(__file__), 'yara_rules')
        
        if not os.path.exists(rules_dir):
            logger.warning(f"[YARA] Rules directory not found: {rules_dir}")
            return None
        
        rule_files = {}
        for filename in os.listdir(rules_dir):
            if filename.endswith(('.yar', '.yara')):
                filepath = os.path.join(rules_dir, filename)
                rule_files[filename] = filepath
                logger.info(f"[YARA] Found rule file: {filename}")
        
        if not rule_files:
            logger.warning("[YARA] No rule files found")
            return None
        
        try:
            rules = yara.compile(filepaths=rule_files)
            logger.info(f"[YARA] Successfully compiled {len(rule_files)} rule files")
            return rules
        except Exception as e:
            logger.error(f"[YARA] Failed to compile rules: {e}")
            return None

    def calculate_hashes(self, filepath: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, SHA256 hashes"""
        hashes = {}
        
        with open(filepath, 'rb') as f:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
            
            hashes['md5'] = md5.hexdigest()
            hashes['sha1'] = sha1.hexdigest()
            hashes['sha256'] = sha256.hexdigest()
        
        return hashes

    def calculate_entropy(self, filepath: str) -> float:
        """Calculate Shannon entropy (0-8 scale)"""
        with open(filepath, 'rb') as f:
            # Read first 1MB for entropy calculation
            data = f.read(1024 * 1024)
        
        if not data:
            return 0.0
        
        entropy = 0.0
        data_len = len(data)
        
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        for count in byte_counts.values():
            p_x = count / data_len
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        
        return round(entropy, 2)

    def detect_file_type(self, filepath: str) -> Dict[str, str]:
        """Detect actual file type using magic numbers"""
        if MAGIC_AVAILABLE:
            try:
                file_type = magic.from_file(filepath)
                mime_type = magic.from_file(filepath, mime=True)
                return {'description': file_type, 'mime': mime_type}
            except Exception as e:
                logger.warning(f"[MAGIC] Detection failed: {e}")
        
        # Fallback: basic detection from file header
        return self._basic_file_detection(filepath)

    def _basic_file_detection(self, filepath: str) -> Dict[str, str]:
        """Basic file type detection from headers"""
        with open(filepath, 'rb') as f:
            header = f.read(32)
        
        # Common signatures
        signatures = {
            b'\x4D\x5A': 'PE32 executable (Windows)',
            b'\x7FELF': 'ELF executable (Linux)',
            b'\xCF\xFA\xED\xFE': 'Mach-O executable (macOS)',
            b'\xCA\xFE\xBA\xBE': 'Java class file',
            b'PK\x03\x04': 'ZIP archive (possibly APK/JAR/DOCX)',
            b'%PDF': 'PDF document',
            b'\xFF\xD8\xFF': 'JPEG image',
            b'\x89PNG': 'PNG image',
            b'GIF8': 'GIF image',
            b'\x25\x50\x44\x46': 'PDF document',
        }
        
        for sig, desc in signatures.items():
            if header.startswith(sig):
                return {'description': desc, 'mime': 'application/octet-stream'}
        
        return {'description': 'Unknown', 'mime': 'application/octet-stream'}

    def check_extension_mismatch(self, filepath: str, detected_type: str) -> tuple:
        """Check if file extension matches actual type"""
        filename = os.path.basename(filepath).lower()
        
        if '.' not in filename:
            return False, None
        
        ext = filename.rsplit('.', 1)[-1]
        
        # Dangerous extension combos
        dangerous = {
            'exe': ['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'txt', 'zip'],
            'scr': ['pdf', 'doc', 'jpg', 'png', 'txt'],
            'com': ['pdf', 'doc', 'jpg', 'png'],
            'bat': ['txt', 'log'],
            'cmd': ['txt', 'log'],
            'ps1': ['txt'],
            'vbs': ['txt'],
        }
        
        # Check for spoofing patterns like "invoice.pdf.exe"
        for dangerous_ext, disguised_as in dangerous.items():
            for disguise in disguised_as:
                spoof_pattern = f'.{disguise}.{dangerous_ext}'
                if spoof_pattern in filename:
                    return True, f"Extension spoofing: .{dangerous_ext} disguised as .{disguise}"
        
        # Check if detected type matches extension
        type_keywords = {
            'exe': ['pe32', 'executable', 'ms-dos'],
            'dll': ['pe32', 'dll'],
            'pdf': ['pdf'],
            'doc': ['microsoft word', 'composite document'],
            'docx': ['microsoft word', 'openxml'],
            'jpg': ['jpeg', 'jfif'],
            'jpeg': ['jpeg', 'jfif'],
            'png': ['png'],
            'zip': ['zip archive'],
        }
        
        detected_lower = detected_type.lower()
        expected = type_keywords.get(ext, [ext])
        
        if ext in type_keywords:
            matches = any(kw in detected_lower for kw in expected)
            if not matches and 'executable' in detected_lower:
                return True, f"Extension .{ext} but detected as: {detected_type}"
        
        return False, None

    def scan_with_yara(self, filepath: str) -> List[Dict]:
        """Scan file with YARA rules"""
        if not self.yara_rules:
            return []
        
        try:
            matches = self.yara_rules.match(filepath)
            findings = []
            
            for match in matches:
                finding = {
                    'type': 'yara_match',
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags) if match.tags else [],
                    'meta': dict(match.meta) if match.meta else {},
                    'severity': 'critical' if 'malware' in (match.tags or []) else 'high'
                }
                findings.append(finding)
            
            return findings
        except Exception as e:
            logger.error(f"[YARA] Scan failed: {e}")
            return []

    def check_virustotal(self, file_hash: str) -> Optional[Dict]:
        """Check file hash against VirusTotal"""
        if not VIRUSTOTAL_API_KEY:
            logger.debug("[VT] No API key configured")
            return None
        
        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    'found': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'total': sum(stats.values()),
                    'reputation': attributes.get('reputation', 0),
                    'first_seen': attributes.get('first_submission_date'),
                    'last_seen': attributes.get('last_analysis_date')
                }
            elif response.status_code == 404:
                return {'found': False, 'message': 'File not found in VirusTotal'}
            else:
                logger.warning(f"[VT] API error: {response.status_code}")
                return {'found': False, 'message': f'API error: {response.status_code}'}
                
        except Exception as e:
            logger.error(f"[VT] Request failed: {e}")
            return {'found': False, 'message': str(e)}

    def analyze_pe_structure(self, filepath: str) -> List[Dict]:
        """Basic PE (Windows executable) analysis"""
        findings = []
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read(512)  # Read PE header
            
            if len(data) < 64 or data[:2] != b'MZ':
                return findings
            
            # Get PE header offset
            pe_offset = int.from_bytes(data[60:64], 'little')
            
            if pe_offset + 24 > len(data):
                return findings
            
            # Check PE signature
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                findings.append({
                    'type': 'pe_anomaly',
                    'description': 'Invalid PE signature',
                    'severity': 'medium'
                })
                return findings
            
            # Read characteristics
            characteristics = int.from_bytes(data[pe_offset+22:pe_offset+24], 'little')
            
            # Check characteristics
            if characteristics & 0x2000:  # DLL
                findings.append({
                    'type': 'pe_info',
                    'description': 'File is a DLL (Dynamic Link Library)',
                    'severity': 'info'
                })
            
            if not (characteristics & 0x0001):  # Relocations stripped
                findings.append({
                    'type': 'pe_suspicious',
                    'description': 'Relocations stripped (common in packed malware)',
                    'severity': 'medium'
                })
            
        except Exception as e:
            logger.error(f"[PE] Analysis failed: {e}")
        
        return findings

    def scan_file(self, filepath: str, filename: str) -> Dict[str, Any]:
        """Main file scanning function"""
        logger.info(f"[SCAN] Starting scan of: {filename}")
        
        # Initialize result
        result = {
            'filename': filename,
            'size': os.path.getsize(filepath),
            'hashes': {},
            'file_type': {},
            'entropy': 0.0,
            'entropy_analysis': {},
            'findings': [],
            'virustotal': None,
            'threat_score': 0,
            'threat_level': 'safe',
            'scan_time': datetime.utcnow().isoformat()
        }
        
        try:
            # Calculate hashes
            result['hashes'] = self.calculate_hashes(filepath)
            
            # Detect file type
            result['file_type'] = self.detect_file_type(filepath)
            
            # Calculate entropy
            result['entropy'] = self.calculate_entropy(filepath)
            result['entropy_analysis'] = {
                'value': result['entropy'],
                'interpretation': 'High entropy - likely packed/encrypted' if result['entropy'] > 7.5 else 
                                'Medium entropy - possibly compressed' if result['entropy'] > 6.5 else
                                'Normal entropy'
            }
            
            # Check extension mismatch
            is_mismatch, mismatch_reason = self.check_extension_mismatch(
                filepath, result['file_type']['description']
            )
            if is_mismatch:
                result['findings'].append({
                    'type': 'extension_mismatch',
                    'description': mismatch_reason,
                    'severity': 'high'
                })
            
            # PE analysis for executables
            if 'executable' in result['file_type']['description'].lower() or \
               'pe32' in result['file_type']['description'].lower():
                pe_findings = self.analyze_pe_structure(filepath)
                result['findings'].extend(pe_findings)
            
            # YARA scan
            yara_matches = self.scan_with_yara(filepath)
            result['findings'].extend(yara_matches)
            
            # VirusTotal check
            result['virustotal'] = self.check_virustotal(result['hashes']['sha256'])
            
            # Calculate threat score
            result['threat_score'] = self._calculate_threat_score(result)
            result['threat_level'] = self._determine_threat_level(result)
            
            logger.info(f"[SCAN] Complete - Score: {result['threat_score']}, Level: {result['threat_level']}")
            
        except Exception as e:
            logger.error(f"[SCAN] Error scanning file: {e}")
            result['findings'].append({
                'type': 'error',
                'description': f'Scan error: {str(e)}',
                'severity': 'low'
            })
        
        return result

    def _calculate_threat_score(self, result: Dict) -> int:
        """Calculate overall threat score (0-100)"""
        score = 0
        findings = result.get('findings', [])
        
        # YARA matches (highest weight)
        yara_matches = [f for f in findings if f.get('type') == 'yara_match']
        score += len(yara_matches) * 15
        
        # Suspicious strings/behaviors
        suspicious = [f for f in findings if f.get('severity') == 'high']
        score += len(suspicious) * 10
        
        # Medium severity
        medium = [f for f in findings if f.get('severity') == 'medium']
        score += len(medium) * 5
        
        # Entropy score
        if result['entropy'] > 7.5:
            score += 20
        elif result['entropy'] > 7.0:
            score += 10
        
        # VirusTotal results
        vt = result.get('virustotal')
        if vt and vt.get('found'):
            malicious = vt.get('malicious', 0)
            score += min(malicious * 3, 30)
        
        # Extension mismatch
        mismatch = [f for f in findings if f.get('type') == 'extension_mismatch']
        score += len(mismatch) * 25
        
        return min(score, 100)

    def _determine_threat_level(self, result: Dict) -> str:
        """Determine threat level from score and findings"""
        score = result['threat_score']
        vt = result.get('virustotal')
        
        # Critical: VirusTotal shows malware
        if vt and vt.get('malicious', 0) >= 5:
            return 'critical'
        
        # Critical: High score
        if score >= 80:
            return 'critical'
        
        # High: Medium-high score or some VT detections
        if score >= 60 or (vt and vt.get('malicious', 0) >= 2):
            return 'high'
        
        # Medium: Moderate score
        if score >= 30:
            return 'medium'
        
        # Low: Some findings
        if score >= 10:
            return 'low'
        
        return 'safe'


# Singleton instance
_scanner = None

def get_scanner() -> FileScanner:
    """Get or create scanner singleton"""
    global _scanner
    if _scanner is None:
        _scanner = FileScanner()
    return _scanner


def scan_file(filepath: str, filename: str) -> Dict[str, Any]:
    """Convenience function to scan a file"""
    scanner = get_scanner()
    return scanner.scan_file(filepath, filename)
