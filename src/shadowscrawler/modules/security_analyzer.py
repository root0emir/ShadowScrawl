#!/usr/bin/env python3

"""
Security Analyzer Module

Performs security analysis on websites:
- TLS/SSL certificate validation
- Security header checks
- Common vulnerability detection
- Basic security scoring
"""

import re
import logging
import socket
import ssl
import datetime
from typing import Dict, List, Set, Any, Optional, Tuple
import httpx
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from shadowscrawler.modules.color import color


class SecurityAnalyzer:
    """
    Analyzes security aspects of web pages including TLS certificates,
    security headers, and basic vulnerability checks
    """
    
    # List of known vulnerable JavaScript libraries and their patched versions
    VULNERABLE_JS_LIBS = {
        'jquery': {
            'pattern': r'jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            'vulnerable': [
                {'version': '1.12.4', 'below': True, 'cve': 'CVE-2020-11023'},
                {'version': '3.4.0', 'below': True, 'cve': 'CVE-2019-11358'},
                # Add more known vulnerable versions
            ]
        },
        'bootstrap': {
            'pattern': r'bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
            'vulnerable': [
                {'version': '4.3.1', 'below': True, 'cve': 'CVE-2019-8331'},
                {'version': '3.4.0', 'below': True, 'cve': 'CVE-2018-14040'},
                # Add more known vulnerable versions
            ]
        }
    }
    
    # Important security headers to check
    SECURITY_HEADERS = [
        'strict-transport-security',
        'content-security-policy',
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy',
    ]
    
    def __init__(self, client: httpx.Client):
        """
        Initialize the security analyzer
        
        Args:
            client: HTTP client for making requests
        """
        self.client = client
        self.logger = logging.getLogger(__name__)
    
    def analyze_security(self, url: str, response: httpx.Response = None) -> Dict[str, Any]:
        """
        Perform a comprehensive security analysis of a website
        
        Args:
            url: URL to analyze
            response: Optional HTTP response if already fetched
            
        Returns:
            Dictionary with security analysis results
        """
        result = {
            'url': url,
            'tls_certificate': None,
            'security_headers': {},
            'vulnerabilities': [],
            'security_score': 0,
            'recommendations': []
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            
            # Check TLS certificate for non-onion sites
            if not parsed_url.netloc.endswith('.onion') and parsed_url.scheme == 'https':
                result['tls_certificate'] = self.analyze_tls_certificate(parsed_url.netloc)
            
            # Get response if not provided
            if response is None:
                try:
                    response = self.client.get(url, follow_redirects=True)
                except Exception as e:
                    self.logger.error(f"Error fetching URL: {e}")
                    result['vulnerabilities'].append({
                        'type': 'connection_error',
                        'details': str(e),
                        'severity': 'medium'
                    })
                    return result
            
            # Analyze security headers
            result['security_headers'] = self.analyze_security_headers(response.headers)
            
            # Check for common vulnerabilities in HTML content
            vulnerabilities = self.check_vulnerabilities(url, response)
            result['vulnerabilities'].extend(vulnerabilities)
            
            # Calculate security score
            result['security_score'] = self.calculate_security_score(result)
            
            # Generate recommendations
            result['recommendations'] = self.generate_recommendations(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in security analysis: {e}")
            return {
                'url': url,
                'error': str(e),
                'security_score': 0
            }
    
    def analyze_tls_certificate(self, hostname: str) -> Dict[str, Any]:
        """
        Analyze the TLS/SSL certificate of a website
        
        Args:
            hostname: The hostname to check
            
        Returns:
            Dictionary with certificate information
        """
        try:
            # Create an SSL context
            context = ssl.create_default_context()
            
            # Connect to the host
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get the certificate
                    cert = ssock.getpeercert()
                    
                    # Parse certificate information
                    not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    # Check if the certificate is expired or about to expire
                    now = datetime.datetime.now()
                    days_left = (not_after - now).days
                    is_expired = days_left < 0
                    is_expiring_soon = 0 <= days_left <= 30
                    
                    # Get the issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    issuer_name = issuer.get('organizationName', 'Unknown')
                    
                    # Get the subject
                    subject = dict(x[0] for x in cert['subject'])
                    subject_name = subject.get('commonName', hostname)
                    
                    # Check for wildcard certificate
                    is_wildcard = subject_name.startswith('*.')
                    
                    return {
                        'valid': True,
                        'issuer': issuer_name,
                        'subject': subject_name,
                        'expiration_date': not_after.strftime('%Y-%m-%d'),
                        'days_until_expiry': days_left,
                        'is_expired': is_expired,
                        'is_expiring_soon': is_expiring_soon,
                        'is_wildcard': is_wildcard
                    }
                    
        except ssl.SSLError as e:
            return {
                'valid': False,
                'error': f"SSL Error: {str(e)}",
                'details': "Certificate validation failed"
            }
        except socket.error as e:
            return {
                'valid': False,
                'error': f"Connection Error: {str(e)}",
                'details': "Could not establish connection"
            }
        except Exception as e:
            return {
                'valid': False,
                'error': f"General Error: {str(e)}",
                'details': "Unknown error occurred during certificate check"
            }
    
    def analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze security headers in HTTP response
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Dictionary with header analysis
        """
        result = {
            'present': {},
            'missing': [],
            'score': 0
        }
        
        # Check for security headers
        max_score = len(self.SECURITY_HEADERS)
        score = 0
        
        for header in self.SECURITY_HEADERS:
            header_value = headers.get(header, None)
            if header_value:
                result['present'][header] = header_value
                score += 1
            else:
                result['missing'].append(header)
        
        # Calculate score as percentage
        if max_score > 0:
            result['score'] = (score / max_score) * 100
        
        return result
    
    def check_vulnerabilities(self, url: str, response: httpx.Response) -> List[Dict[str, Any]]:
        """
        Check for common vulnerabilities
        
        Args:
            url: The URL being analyzed
            response: HTTP response
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Parse the HTML
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for vulnerable JavaScript libraries
            vulnerabilities.extend(self._check_vulnerable_js_libs(soup))
            
            # Check for insecure form submissions
            if soup.find('form', action=lambda x: x and x.startswith('http:')):
                vulnerabilities.append({
                    'type': 'insecure_form',
                    'details': 'Form submits data over unencrypted HTTP',
                    'severity': 'high'
                })
            
            # Check for missing CSRF tokens in forms
            forms = soup.find_all('form')
            for form in forms:
                if not form.find('input', {'name': re.compile('csrf|token', re.IGNORECASE)}):
                    vulnerabilities.append({
                        'type': 'missing_csrf_token',
                        'details': 'Form does not contain a CSRF token',
                        'severity': 'medium'
                    })
            
            # Check for potentially dangerous JavaScript events
            dangerous_events = ['onerror', 'onload', 'onclick', 'onmouseover']
            for event in dangerous_events:
                elements = soup.find_all(attrs={event: True})
                if elements:
                    vulnerabilities.append({
                        'type': 'inline_js_event',
                        'details': f'Inline JavaScript {event} event found',
                        'severity': 'low'
                    })
                    break
            
            # Check response for error codes that may indicate vulnerabilities
            if 300 <= response.status_code < 400:
                vulnerabilities.append({
                    'type': 'redirect',
                    'details': f'Redirects to {response.headers.get("location", "unknown")}',
                    'severity': 'info'
                })
            elif response.status_code >= 400:
                vulnerabilities.append({
                    'type': 'http_error',
                    'details': f'HTTP error {response.status_code}',
                    'severity': 'info'
                })
                
        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities: {e}")
            vulnerabilities.append({
                'type': 'analysis_error',
                'details': f'Error during vulnerability analysis: {str(e)}',
                'severity': 'info'
            })
        
        return vulnerabilities
    
    def _check_vulnerable_js_libs(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """
        Check for known vulnerable JavaScript libraries
        
        Args:
            soup: BeautifulSoup object of the parsed HTML
            
        Returns:
            List of detected vulnerable libraries
        """
        vulnerabilities = []
        
        # Find all script tags with src attribute
        script_tags = soup.find_all('script', src=True)
        
        for script in script_tags:
            src = script.get('src', '')
            
            # Check against known vulnerable libraries
            for lib_name, lib_data in self.VULNERABLE_JS_LIBS.items():
                match = re.search(lib_data['pattern'], src)
                if match:
                    version = match.group(1)
                    
                    # Check if version is vulnerable
                    for vuln in lib_data['vulnerable']:
                        if vuln['below'] and self._is_version_below(version, vuln['version']):
                            vulnerabilities.append({
                                'type': 'vulnerable_js_library',
                                'details': f'{lib_name} version {version} is vulnerable to {vuln["cve"]}',
                                'library': lib_name,
                                'version': version,
                                'cve': vuln['cve'],
                                'severity': 'high'
                            })
        
        return vulnerabilities
    
    def _is_version_below(self, version: str, target_version: str) -> bool:
        """
        Check if a version is below the target version
        
        Args:
            version: The version to check
            target_version: The target version to compare against
            
        Returns:
            True if version is below target_version, False otherwise
        """
        try:
            version_parts = list(map(int, version.split('.')))
            target_parts = list(map(int, target_version.split('.')))
            
            # Pad with zeros if needed
            while len(version_parts) < len(target_parts):
                version_parts.append(0)
            while len(target_parts) < len(version_parts):
                target_parts.append(0)
            
            # Compare version parts
            for i in range(len(version_parts)):
                if version_parts[i] < target_parts[i]:
                    return True
                elif version_parts[i] > target_parts[i]:
                    return False
            
            # If we get here, versions are equal
            return False
            
        except Exception:
            # If parsing fails, assume it's not vulnerable
            return False
    
    def calculate_security_score(self, result: Dict[str, Any]) -> int:
        """
        Calculate a security score based on findings
        
        Args:
            result: Dictionary with security analysis results
            
        Returns:
            Security score (0-100)
        """
        score = 100
        
        # TLS certificate issues
        if result['tls_certificate']:
            if not result['tls_certificate'].get('valid', False):
                score -= 30
            elif result['tls_certificate'].get('is_expired', False):
                score -= 30
            elif result['tls_certificate'].get('is_expiring_soon', False):
                score -= 10
        
        # Security headers
        if 'security_headers' in result and 'score' in result['security_headers']:
            # Weight security headers as 30% of total score
            header_score = result['security_headers']['score'] * 0.3
            score -= 30 - header_score
        
        # Vulnerabilities
        for vuln in result.get('vulnerabilities', []):
            severity = vuln.get('severity', 'medium')
            if severity == 'critical':
                score -= 20
            elif severity == 'high':
                score -= 15
            elif severity == 'medium':
                score -= 10
            elif severity == 'low':
                score -= 5
        
        # Ensure score is between 0 and 100
        return max(0, min(100, int(score)))
    
    def generate_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on findings
        
        Args:
            result: Dictionary with security analysis results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Certificate recommendations
        tls_cert = result.get('tls_certificate')
        if tls_cert:
            if not tls_cert.get('valid', False):
                recommendations.append("Fix SSL/TLS certificate issues.")
            elif tls_cert.get('is_expired', False):
                recommendations.append("Renew the expired SSL/TLS certificate.")
            elif tls_cert.get('is_expiring_soon', False):
                recommendations.append(f"Renew SSL/TLS certificate soon (expires in {tls_cert.get('days_until_expiry', 0)} days).")
        
        # Security header recommendations
        sec_headers = result.get('security_headers', {})
        missing_headers = sec_headers.get('missing', [])
        
        if 'strict-transport-security' in missing_headers:
            recommendations.append("Add HTTP Strict Transport Security (HSTS) header.")
        
        if 'content-security-policy' in missing_headers:
            recommendations.append("Implement Content Security Policy (CSP) to prevent XSS attacks.")
        
        if 'x-content-type-options' in missing_headers:
            recommendations.append("Add X-Content-Type-Options header with 'nosniff' value.")
        
        if 'x-frame-options' in missing_headers:
            recommendations.append("Add X-Frame-Options header to prevent clickjacking.")
        
        # Vulnerability-specific recommendations
        for vuln in result.get('vulnerabilities', []):
            vuln_type = vuln.get('type')
            
            if vuln_type == 'vulnerable_js_library':
                recommendations.append(f"Update {vuln.get('library')} to a non-vulnerable version.")
            
            elif vuln_type == 'insecure_form':
                recommendations.append("Ensure all forms submit data over HTTPS.")
            
            elif vuln_type == 'missing_csrf_token':
                recommendations.append("Add CSRF tokens to all forms to prevent cross-site request forgery.")
        
        return recommendations
    
    def print_security_report(self, result: Dict[str, Any]) -> None:
        """
        Print a formatted security report
        
        Args:
            result: Dictionary with security analysis results
        """
        print("\n" + color("═" * 70, "cyan"))
        print(color(" SECURITY ANALYSIS REPORT ", "cyan"))
        print(color("═" * 70, "cyan"))
        
        # Print URL
        print(f"\nURL: {result['url']}")
        
        # Print security score with color
        score = result['security_score']
        score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        print(f"\nSecurity Score: {color(str(score) + '/100', score_color)}")
        
        # Print TLS certificate information
        print(color("\n[TLS Certificate]", "green"))
        tls_cert = result.get('tls_certificate')
        if tls_cert:
            if tls_cert.get('valid', False):
                print(f"  • Status: {color('Valid', 'green')}")
                print(f"  • Issuer: {tls_cert.get('issuer', 'Unknown')}")
                print(f"  • Expires: {tls_cert.get('expiration_date', 'Unknown')}")
                
                days = tls_cert.get('days_until_expiry', 0)
                if days < 0:
                    print(f"  • Expiration: {color('EXPIRED', 'red')}")
                elif days <= 30:
                    print(f"  • Expiration: {color(f'Expires in {days} days', 'yellow')}")
                else:
                    print(f"  • Expiration: {color(f'Valid for {days} days', 'green')}")
            else:
                print(f"  • Status: {color('Invalid', 'red')}")
                print(f"  • Error: {tls_cert.get('error', 'Unknown error')}")
        else:
            print("  Certificate information not available")
        
        # Print security headers
        print(color("\n[Security Headers]", "green"))
        sec_headers = result.get('security_headers', {})
        present = sec_headers.get('present', {})
        missing = sec_headers.get('missing', [])
        
        if present:
            print("  Present:")
            for header, value in present.items():
                print(f"  • {color(header, 'green')}: {value[:50] + '...' if len(value) > 50 else value}")
        
        if missing:
            print("  Missing:")
            for header in missing:
                print(f"  • {color(header, 'red')}")
        
        # Print vulnerabilities
        print(color("\n[Vulnerabilities]", "green"))
        vulns = result.get('vulnerabilities', [])
        if vulns:
            for vuln in vulns:
                severity = vuln.get('severity', 'medium')
                severity_color = {
                    'critical': 'red', 'high': 'red', 'medium': 'yellow',
                    'low': 'green', 'info': 'cyan'
                }.get(severity, 'white')
                
                print(f"  • {color(severity.upper(), severity_color)}: {vuln.get('details', 'Unknown vulnerability')}")
        else:
            print("  No vulnerabilities detected")
        
        # Print recommendations
        print(color("\n[Recommendations]", "green"))
        recommendations = result.get('recommendations', [])
        if recommendations:
            for i, recommendation in enumerate(recommendations, 1):
                print(f"  {i}. {recommendation}")
        else:
            print("  No specific recommendations")
        
        print("\n" + color("═" * 70, "cyan") + "\n")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import httpx
    
    with httpx.Client() as client:
        analyzer = SecurityAnalyzer(client)
        url = "https://example.com"
        response = client.get(url)
        results = analyzer.analyze_security(url, response)
        analyzer.print_security_report(results)
