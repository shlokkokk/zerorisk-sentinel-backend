"""
ZeroRisk Sentinel - URL Security Scanner
"""

import os
import re
import ssl
import socket
import requests
import logging
import base64
from typing import Dict, Any
from urllib.parse import urlparse
from datetime import datetime

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logging.warning("[URL] dnspython not available")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


class URLScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        result = {
            'url': url,
            'domain': domain,
            'scan_time': datetime.utcnow().isoformat(),
            'threat_score': 0,
            'threat_level': 'safe',
            'findings': [],
            'services': {},
            'backend_based': True
        }
        
        # Run all checks
        result['services']['google_safe_browsing'] = self.check_google_safe_browsing(url)
        result['services']['urlhaus'] = self.check_urlhaus(url)
        result['services']['virustotal_url'] = self.check_virustotal_url(url)
        result['services']['dns'] = self.analyze_dns(domain)
        result['services']['redirects'] = self.follow_redirects(url)
        
        if parsed.scheme == 'https':
            result['services']['ssl'] = self.analyze_ssl_cert(domain)
        else:
            result['services']['ssl'] = {'has_ssl': False}
            result['findings'].append({
                'type': 'no_https',
                'severity': 'medium',
                'description': 'Connection does not use HTTPS'
            })
            result['threat_score'] += 15
        
        result['services']['domain_age'] = self.get_domain_age(domain)
        
        # Local heuristics
        heuristic = self.heuristic_analysis(url, parsed)
        result['heuristic'] = heuristic
        result['findings'].extend(heuristic['findings'])
        result['threat_score'] += heuristic['score']
        
        # Boost score from external services
        gsb = result['services'].get('google_safe_browsing', {})
        if gsb.get('threat_found'):
            result['threat_score'] += 40
        
        uh = result['services'].get('urlhaus', {})
        if uh.get('listed'):
            result['threat_score'] += 35
        
        vt = result['services'].get('virustotal_url', {})
        if vt and vt.get('found'):
            result['threat_score'] += min(vt.get('malicious', 0) * 5, 25)
        
        # Final score
        result['threat_score'] = min(result['threat_score'], 100)
        result['threat_level'] = self._determine_threat_level(result)
        result['explanation'] = self._generate_explanation(result)
        
        return result
    
    def check_google_safe_browsing(self, url: str) -> Dict:
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return {'available': False, 'note': 'API key not configured'}
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
            payload = {
                "client": {"clientId": "zerorisk-sentinel", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            response = self.session.post(api_url, json=payload, timeout=8)
            data = response.json()
            
            if data.get("matches"):
                match = data["matches"][0]
                return {
                    'available': True,
                    'threat_found': True,
                    'threat_type': match.get("threatType"),
                    'platform': match.get("platformType")
                }
            return {'available': True, 'threat_found': False, 'safe': True}
        except Exception as e:
            logger.error(f"[GSB] Error: {e}")
            return {'available': False, 'error': str(e)}
    
    def check_urlhaus(self, url: str) -> Dict:
        try:
            response = self.session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=5
            )
            data = response.json()
            if data.get("query_status") == "ok":
                return {
                    'available': True,
                    'listed': True,
                    'threat': data.get("threat"),
                    'date_added': data.get("date_added")
                }
            return {'available': True, 'listed': False}
        except Exception as e:
            logger.error(f"[URLHaus] Error: {e}")
            return {'available': False}
    
    def check_virustotal_url(self, url: str) -> Dict:
        if not VIRUSTOTAL_API_KEY:
            return {'available': False, 'note': 'API key not configured'}
        
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            response = self.session.get(api_url, headers=headers, timeout=8)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'available': True,
                    'found': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'total': sum(stats.values())
                }
            elif response.status_code == 404:
                return {'available': True, 'found': False}
            return {'available': False, 'error': f'Status {response.status_code}'}
        except Exception as e:
            logger.error(f"[VT-URL] Error: {e}")
            return {'available': False}
    
    def analyze_dns(self, domain: str) -> Dict:
        if not DNS_AVAILABLE:
            return {'available': False, 'note': 'dnspython not installed'}
        
        result = {
            'available': True, 
            'has_a': False, 
            'has_mx': False, 
            'has_spf': False,
            'a_records': [],
            'mx_records': [],
            'error': None
        }
        
        try:
            # A records
            a_records = dns.resolver.resolve(domain, 'A')
            result['has_a'] = True
            result['a_records'] = [str(r) for r in a_records]
            logger.info(f"[DNS] {domain} A records: {result['a_records']}")
        except Exception as e:
            logger.warning(f"[DNS] A record lookup failed for {domain}: {e}")
            result['error'] = f"A record: {str(e)}"
        
        try:
            # MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['has_mx'] = True
            result['mx_records'] = [str(r.exchange) for r in mx_records]
            logger.info(f"[DNS] {domain} MX records: {result['mx_records']}")
        except Exception as e:
            logger.warning(f"[DNS] MX record lookup failed for {domain}: {e}")
        
        try:
            # SPF from TXT
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for t in txt_records:
                txt_str = str(t)
                if 'v=spf1' in txt_str:
                    result['has_spf'] = True
                    result['spf_record'] = txt_str
                    logger.info(f"[DNS] {domain} SPF found")
                    break
        except Exception as e:
            logger.warning(f"[DNS] TXT/SPF lookup failed for {domain}: {e}")
        
        return result
    
    def follow_redirects(self, url: str, max_hops: int = 5) -> Dict:
        redirects = []
        current = url
        try:
            for i in range(max_hops):
                r = self.session.head(current, allow_redirects=False, timeout=5)
                if r.status_code in [301, 302, 307, 308]:
                    loc = r.headers.get('Location', '')
                    if loc.startswith('/'):
                        parsed = urlparse(current)
                        loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                    redirects.append({'hop': i+1, 'from': current[:50], 'to': loc[:50]})
                    current = loc
                else:
                    break
            return {
                'available': True,
                'count': len(redirects),
                'redirects': redirects,
                'suspicious': len(redirects) > 3
            }
        except Exception as e:
            return {'available': False, 'error': str(e)}
    
    def analyze_ssl_cert(self, domain: str) -> Dict:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days = (not_after - datetime.now()).days
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    return {
                        'available': True,
                        'has_ssl': True,
                        'days_left': days,
                        'expired': days < 0,
                        'self_signed': issuer == subject,
                        'suspicious': days < 7 or issuer == subject
                    }
        except:
            return {'available': False, 'has_ssl': False}
    
    def get_domain_age(self, domain: str) -> Dict:
        if not WHOIS_AVAILABLE:
            return {'available': False}
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                days = (datetime.now() - created).days
                return {
                    'available': True,
                    'days': days,
                    'suspicious': days < 30
                }
        except:
            pass
        return {'available': False}
    
    def heuristic_analysis(self, url: str, parsed) -> Dict:
        findings = []
        score = 0
        host = parsed.netloc.lower()
        
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            score += 30
            findings.append({'type': 'ip_url', 'severity': 'high', 'description': 'URL uses raw IP address'})
        
        if re.search(r'(login|verify|secure|bank|password|account|update)', url, re.I):
            score += 20
            findings.append({'type': 'phishing_words', 'severity': 'medium', 'description': 'Phishing keywords detected'})
        
        if re.search(r'(bit\.ly|tinyurl|t\.co|ow\.ly|cutt\.ly|rb\.gy|short\.link)', url, re.I):
            score += 25
            findings.append({'type': 'shortener', 'severity': 'high', 'description': 'URL shortener detected'})
        
        if re.search(r'\.(xyz|tk|ml|ga|cf|top|icu)$', url, re.I):
            score += 20
            findings.append({'type': 'risky_tld', 'severity': 'medium', 'description': 'High-risk TLD'})
        
        if len(parsed.path) > 50:
            score += 10
            findings.append({'type': 'long_path', 'severity': 'low', 'description': 'Unusually long URL path'})
        
        return {'score': min(score, 50), 'findings': findings}
    
    def _determine_threat_level(self, result: Dict) -> str:
        score = result['threat_score']
        
        gsb = result['services'].get('google_safe_browsing', {})
        if gsb.get('threat_found'):
            return 'critical'
        
        uh = result['services'].get('urlhaus', {})
        if uh.get('listed'):
            return 'critical'
        
        vt = result['services'].get('virustotal_url', {})
        if vt and vt.get('malicious', 0) >= 5:
            return 'critical'
        if vt and vt.get('malicious', 0) >= 2:
            return 'high'
        
        if score >= 80: return 'critical'
        if score >= 60: return 'high'
        if score >= 30: return 'medium'
        if score >= 10: return 'low'
        return 'safe'
    
    def _generate_explanation(self, result: Dict) -> str:
        parts = []
        
        gsb = result['services'].get('google_safe_browsing', {})
        if gsb.get('threat_found'):
            parts.append(f"Google Safe Browsing flagged this as {gsb.get('threat_type')}.")
        
        uh = result['services'].get('urlhaus', {})
        if uh.get('listed'):
            parts.append(f"URLHaus lists this URL as malware distribution.")
        
        vt = result['services'].get('virustotal_url', {})
        if vt and vt.get('malicious', 0) > 0:
            parts.append(f"VirusTotal: {vt['malicious']} security vendors flagged this URL.")
        
        for f in result['findings'][:2]:
            parts.append(f['description'])
        
        if not parts:
            return "No significant threats detected from backend analysis."
        
        return " ".join(parts) + " (Backend-based analysis)"


def scan_url(url: str) -> Dict[str, Any]:
    scanner = URLScanner()
    return scanner.analyze_url(url)