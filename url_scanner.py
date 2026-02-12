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
import time
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

#new stuff added starts here
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

class URLScanIOScanner:
    """urlscan.io sandbox scanner for deep URL analysis"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZeroRisk-Sentinel/1.0',
            'API-Key': URLSCAN_API_KEY
        })
        self.base_url = "https://urlscan.io/api/v1"
    
    def submit_scan(self, url: str, public: bool = True) -> Dict[str, Any]:
        """Submit URL to urlscan.io for sandbox analysis"""
        if not URLSCAN_API_KEY:
            return {
                'success': False,
                'error': 'URLSCAN_API_KEY not configured',
                'note': 'Get free API key from urlscan.io'
            }
        
        try:
            payload = {
                "url": url,
                "public": "on" if public else "off",
                "tags": ["zerorisk-sentinel", "security-scan"]
            }
            
            response = self.session.post(
                f"{self.base_url}/scan/",
                headers={"API-Key": URLSCAN_API_KEY},
                json=payload,
                timeout=30
            )
            
            if response.status_code == 400:
                data = response.json()
                if "message" in data and "already" in data["message"].lower():
                    return {
                        'success': True,
                        'scan_id': data.get("uuid", ""),
                        'message': 'Scan already exists, using existing result',
                        'existing': True
                    }
                return {'success': False, 'error': data.get('message', 'Bad request')}
            
            if response.status_code == 429:
                return {
                    'success': False,
                    'error': 'Rate limit exceeded. urlscan.io free tier: 1 scan/min, 50/day',
                    'rate_limited': True
                }
            
            response.raise_for_status()
            data = response.json()
            
            return {
                'success': True,
                'scan_id': data.get("uuid"),
                'api_url': data.get("api"),
                'result_url': data.get("result"),
                'message': 'Scan submitted successfully'
            }
            
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timed out'}
        except Exception as e:
            logger.error(f"[URLSCAN] Submit error: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_result(self, scan_id: str) -> Dict[str, Any]:
        """Poll urlscan.io for scan results"""
        try:
            response = self.session.get(
                f"{self.base_url}/result/{scan_id}/",
                timeout=15
            )
            
            if response.status_code == 404:
                return {
                    'success': True,
                    'status': 'pending',
                    'message': 'Scan still in progress'
                }
            
            response.raise_for_status()
            data = response.json()
            
            parsed = self._parse_result(data, scan_id)
            parsed['success'] = True
            parsed['status'] = 'completed'
            
            return parsed
            
        except Exception as e:
            logger.error(f"[URLSCAN] Result error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_result(self, data: Dict, scan_id: str) -> Dict[str, Any]:
        """Parse urlscan.io result into our format"""
        logger.info(f"[URLSCAN] Parsing result for scan {scan_id}")
        logger.info(f"[URLSCAN] Data keys: {list(data.keys())}")
        
        # Safely get nested data
        page = data.get("page", {}) or {}
        lists = data.get("lists", {}) or {}
        stats = data.get("stats", {}) or {}
        task = data.get("task", {}) or {}
        data_section = data.get("data", {}) or {}
        
        # Verdicts can be structured differently
        verdicts_section = data.get("verdicts", {}) or {}
        if isinstance(verdicts_section, dict):
            verdicts = verdicts_section.get("overall", {}) or {}
            brands = verdicts_section.get("brands", []) or []
        else:
            verdicts = {}
            brands = []
        
        logger.info(f"[URLSCAN] Verdicts: {verdicts}")
        
        score = 0
        findings = []
        
        brand_names = [b.get("name", "") for b in brands if isinstance(b, dict)]
        
        # Malicious verdict
        if verdicts.get("malicious"):
            score = 85
            findings.append({
                'type': 'malicious_verdict',
                'severity': 'critical',
                'description': 'urlscan.io flagged this page as malicious'
            })
        
        # Suspicious verdict
        if verdicts.get("suspicious"):
            score = max(score, 60)
            findings.append({
                'type': 'suspicious_verdict',
                'severity': 'high',
                'description': 'Suspicious behavior detected in sandbox'
            })
        
        # Phishing detection
        phishing = verdicts.get("phishing", []) if isinstance(verdicts.get("phishing"), list) else []
        if phishing:
            score = max(score, 70)
            for phish in phishing:
                if isinstance(phish, dict):
                    findings.append({
                        'type': 'phishing_detected',
                        'severity': 'high',
                        'description': f"Detected possible {phish.get('brand', 'brand')} impersonation"
                    })
        
        # Brand impersonation check
        if brands:
            for brand in brands:
                if isinstance(brand, dict) and brand.get("detection") == "impersonation":
                    score = max(score, 65)
                    findings.append({
                        'type': 'brand_impersonation',
                        'severity': 'high',
                        'description': f"Page tried to impersonate {brand.get('name', 'a brand')}"
                    })
        
        # Page info
        ip = page.get("ip", "unknown") if isinstance(page, dict) else "unknown"
        asn = page.get("asn", {}) if isinstance(page, dict) else {}
        server = page.get("server", "unknown") if isinstance(page, dict) else "unknown"
        country = page.get("country", "unknown") if isinstance(page, dict) else "unknown"
        domain = page.get("domain", "unknown") if isinstance(page, dict) else "unknown"
        
        # Resource analysis
        resources = lists.get("urls", []) if isinstance(lists, dict) else []
        suspicious_domains = []
        
        for res in resources:
            if isinstance(res, dict):
                res_domain = res.get("domain", "")
                if any(tld in res_domain for tld in ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top']):
                    if res_domain not in suspicious_domains:
                        suspicious_domains.append(res_domain)
        
        if suspicious_domains:
            score = max(score, 40)
            findings.append({
                'type': 'suspicious_resources',
                'severity': 'medium',
                'description': f"Page loaded resources from {len(suspicious_domains)} suspicious domain(s)"
            })
        
        # Network stats
        domains_list = lists.get("domains", []) if isinstance(lists, dict) else []
        ips_list = lists.get("ips", []) if isinstance(lists, dict) else []
        certs_list = lists.get("certificates", []) if isinstance(lists, dict) else []
        asns_list = lists.get("asns", []) if isinstance(lists, dict) else []
        
        network_stats = {
            'total_requests': len(resources),
            'suspicious_domains': len(suspicious_domains),
            'unique_domains': len(domains_list),
            'unique_ips': len(ips_list),
            'certificates': len(certs_list),
            'asns': len(asns_list)
        }
        
        # Console logs
        console = data_section.get("console", []) if isinstance(data_section, dict) else []
        
        # DOM hash
        dom_section = data_section.get("dom", {}) if isinstance(data_section, dict) else {}
        dom_hash = dom_section.get("hash", "") if isinstance(dom_section, dict) else ""
        
        # Meta tags
        meta_tags = page.get("meta", {}) if isinstance(page, dict) else {}
        
        # Screenshot
        screenshot = task.get("screenshotURL", "") if isinstance(task, dict) else ""
        
        # Determine final threat level
        threat_level = 'safe'
        if score >= 80:
            threat_level = 'critical'
        elif score >= 60:
            threat_level = 'high'
        elif score >= 30:
            threat_level = 'medium'
        elif score > 0:
            threat_level = 'low'
        
        # Generate explanation
        explanation = self._generate_explanation(findings, verdicts, network_stats, domain)
        
        return {
            'url': page.get("url", "") if isinstance(page, dict) else "",
            'domain': domain,
            'scan_time': datetime.utcnow().isoformat(),
            'threat_score': score,
            'threat_level': threat_level,
            'findings': findings,
            'explanation': explanation,
            'backend_based': True,
            'deep_scan': True,
            'urlscan_data': {
                'scan_id': scan_id,
                'scan_url': f"https://urlscan.io/result/{scan_id}/",
                'screenshot': screenshot,
                'screenshot_thumb': screenshot,
                'ip': ip,
                'country': country,
                'server': server,
                'asn': {
                    'asn': asn.get("asn") if isinstance(asn, dict) else None,
                    'name': asn.get("name") if isinstance(asn, dict) else None,
                    'country': asn.get("country") if isinstance(asn, dict) else None
                },
                'brands_detected': brand_names,
                'verdicts': {
                    'malicious': verdicts.get("malicious", False) if isinstance(verdicts, dict) else False,
                    'suspicious': verdicts.get("suspicious", False) if isinstance(verdicts, dict) else False,
                    'phishing': len(phishing) > 0,
                    'phishing_details': phishing
                },
                'network_stats': network_stats,
                'suspicious_domains': suspicious_domains,
                'resources_loaded': resources[:20] if resources else [],
                'console_logs': console[:10] if console else [],
                'dom_hash': dom_hash,
                'meta': meta_tags,
                'links': lists.get("links", [])[:10] if isinstance(lists, dict) else [],
                'hashes': {
                    'dom': dom_hash,
                    'requests': stats.get("resourceStats", {}) if isinstance(stats, dict) else {}
                }
            },
            'services': {
                'urlscan_io': {
                    'available': True,
                    'scanned': True,
                    'result_url': f"https://urlscan.io/result/{scan_id}/"
                }
            }
        }
    
    def _generate_explanation(self, findings, verdicts, network_stats, domain):
        """Generate human-readable explanation"""
        parts = []
        
        if verdicts.get("malicious"):
            parts.append("urlscan.io's sandbox detected malicious behavior on this page.")
        
        if verdicts.get("suspicious"):
            parts.append("Suspicious patterns were observed during browser analysis.")
        
        phishing = verdicts.get("phishing", [])
        if phishing:
            brands = ", ".join([p.get("brand", "unknown") for p in phishing])
            parts.append(f"Possible impersonation of: {brands}")
        
        parts.append(f"\nNetwork Activity:")
        parts.append(f"• Made {network_stats['total_requests']} network requests")
        parts.append(f"• Contacted {network_stats['unique_domains']} unique domains")
        parts.append(f"• {network_stats['suspicious_domains']} requests to suspicious domains")
        
        if findings:
            parts.append(f"\nDetected {len(findings)} security indicator(s).")
        
        parts.append(f"\nDomain: {domain}")
        parts.append(f"\n(Deep scan via urlscan.io sandbox - actual browser execution)")
        
        return "\n".join(parts)


def submit_urlscan(url: str) -> Dict[str, Any]:
    """Submit URL to urlscan.io"""
    scanner = URLScanIOScanner()
    return scanner.submit_scan(url)


def get_urlscan_result(scan_id: str) -> Dict[str, Any]:
    """Get urlscan.io result AND run regular scan, then merge them"""
    scanner = URLScanIOScanner()
    urlscan_result = scanner.get_result(scan_id)
    
    # If urlscan completed successfully, also run regular scan
    if urlscan_result.get('success') and urlscan_result.get('status') == 'completed':
        url = urlscan_result.get('url', '')
        if url:
            try:
                # Run regular scan too
                regular_scanner = URLScanner()
                regular_data = regular_scanner.analyze_url(url)
                
                # Merge: urlscan data takes priority, but include regular scan services
                urlscan_result['services'] = {
                    **regular_data.get('services', {}),
                    'urlscan_io': {
                        'available': True,
                        'scanned': True,
                        'result_url': f"https://urlscan.io/result/{scan_id}/"
                    }
                }
                
                # Add any additional findings from regular scan
                existing_types = {f.get('type') for f in urlscan_result.get('findings', [])}
                for finding in regular_data.get('findings', []):
                    if finding.get('type') not in existing_types:
                        urlscan_result['findings'].append(finding)
                
                # Recalculate threat score (take max of both)
                urlscan_result['threat_score'] = max(
                    urlscan_result.get('threat_score', 0),
                    regular_data.get('threat_score', 0)
                )
                
                # Update explanation to mention both
                urlscan_result['explanation'] += f"\n\nAlso checked: Google Safe Browsing, URLHaus, VirusTotal, SSL cert, DNS records."
                
            except Exception as e:
                logger.warning(f"[URLSCAN] Could not run regular scan: {e}")
    
    return urlscan_result