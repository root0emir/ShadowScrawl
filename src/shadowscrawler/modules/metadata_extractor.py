#!/usr/bin/env python3

"""
Metadata Extractor Module

Extracts metadata from web pages including:
- Social media links
- Contact information
- Technologies used
- Document metadata
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any
import httpx
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin, urlparse

from shadowscrawler.modules.color import color


class MetadataExtractor:
    """
    Extracts and analyzes metadata from web pages
    """
    
    # Common social media domains for detection
    SOCIAL_MEDIA_DOMAINS = {
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 
        'youtube.com', 'reddit.com', 'pinterest.com', 'tumblr.com',
        'github.com', 'medium.com', 'telegram.me', 'discord.gg',
        't.me', 'tiktok.com', 'vk.com', 'weibo.com'
    }
    
    # Email pattern for detecting email addresses
    EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    # Bitcoin wallet pattern
    BITCOIN_PATTERN = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
    
    # Common technology signatures in page source
    TECH_SIGNATURES = {
        'WordPress': ['wp-content', 'wp-includes'],
        'Drupal': ['Drupal.settings', 'drupal.org'],
        'Joomla': ['joomla!', '/components/com_'],
        'Bootstrap': ['bootstrap.css', 'bootstrap.js'],
        'jQuery': ['jquery.js', 'jquery.min.js'],
        'React': ['react.js', 'react-dom.js', 'react.production.min.js'],
        'Angular': ['angular.js', 'ng-app', 'ng-controller'],
        'Vue.js': ['vue.js', 'vue.min.js'],
        'Cloudflare': ['cloudflare', '__cf_bm']
    }
    
    def __init__(self, client: httpx.Client):
        """
        Initialize the metadata extractor
        
        Args:
            client: HTTP client for making requests
        """
        self.client = client
        self.logger = logging.getLogger(__name__)
    
    def extract_all(self, url: str, html_content: str) -> Dict[str, Any]:
        """
        Extract all metadata from a given URL and HTML content
        
        Args:
            url: The URL being analyzed
            html_content: The HTML content of the page
            
        Returns:
            Dictionary containing all extracted metadata
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Create the result dictionary
            result = {
                'url': url,
                'social_media': self.extract_social_media_links(url, soup),
                'emails': self.extract_emails(html_content),
                'crypto_addresses': self.extract_crypto_addresses(html_content),
                'technologies': self.detect_technologies(html_content),
                'meta_tags': self.extract_meta_tags(soup),
                'server_info': None  # Will be filled later if headers are available
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error extracting metadata: {e}")
            return {'error': str(e)}
    
    def extract_social_media_links(self, base_url: str, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """
        Extract social media links from the page
        
        Args:
            base_url: The base URL for resolving relative links
            soup: BeautifulSoup object of the parsed HTML
            
        Returns:
            List of dictionaries with platform and link information
        """
        social_links = []
        seen_links = set()
        
        # Check all anchor tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href', '')
            if not href:
                continue
                
            # Resolve relative URLs
            full_url = urljoin(base_url, href)
            parsed_url = urlparse(full_url)
            
            # Check if domain matches any social media platform
            domain_parts = parsed_url.netloc.split('.')
            if len(domain_parts) >= 2:
                domain = f"{domain_parts[-2]}.{domain_parts[-1]}"
                
                # Check if this is a social media domain
                for social_domain in self.SOCIAL_MEDIA_DOMAINS:
                    if social_domain in parsed_url.netloc and full_url not in seen_links:
                        platform = social_domain.split('.')[0]
                        social_links.append({
                            'platform': platform,
                            'url': full_url
                        })
                        seen_links.add(full_url)
                        break
        
        return social_links
    
    def extract_emails(self, html_content: str) -> List[str]:
        """
        Extract email addresses from the page content
        
        Args:
            html_content: The HTML content as a string
            
        Returns:
            List of email addresses
        """
        emails = set()
        
        # Find all email addresses using regex
        matches = re.findall(self.EMAIL_PATTERN, html_content)
        for email in matches:
            # Simple validation to filter out false positives
            if '.' in email.split('@')[1]:
                emails.add(email)
        
        return list(emails)
    
    def extract_crypto_addresses(self, html_content: str) -> List[Dict[str, str]]:
        """
        Extract cryptocurrency addresses from the page
        
        Args:
            html_content: The HTML content as a string
            
        Returns:
            List of dictionaries with crypto type and address
        """
        addresses = []
        
        # Find Bitcoin addresses
        btc_matches = re.findall(self.BITCOIN_PATTERN, html_content)
        for address in btc_matches:
            # Basic validation to reduce false positives
            if len(address) >= 26 and len(address) <= 35:
                addresses.append({
                    'type': 'Bitcoin',
                    'address': address
                })
        
        return addresses
    
    def detect_technologies(self, html_content: str) -> List[str]:
        """
        Detect technologies used in the web page
        
        Args:
            html_content: The HTML content as a string
            
        Returns:
            List of detected technologies
        """
        technologies = []
        
        # Check for technology signatures
        for tech, signatures in self.TECH_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in html_content.lower():
                    technologies.append(tech)
                    break
        
        return technologies
    
    def extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        """
        Extract meta tags from the HTML
        
        Args:
            soup: BeautifulSoup object of the parsed HTML
            
        Returns:
            Dictionary of meta tag names/properties and their content
        """
        meta_data = {}
        
        # Extract standard meta tags
        for meta_tag in soup.find_all('meta'):
            # Get the meta tag name or property
            meta_name = meta_tag.get('name')
            meta_property = meta_tag.get('property')
            meta_content = meta_tag.get('content')
            
            if meta_name and meta_content:
                meta_data[meta_name] = meta_content
            elif meta_property and meta_content:
                meta_data[meta_property] = meta_content
        
        return meta_data
    
    def analyze_server_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze server headers for security and information
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Dictionary with server information analysis
        """
        server_info = {
            'server': headers.get('server', 'Unknown'),
            'security_headers': {
                'x_content_type_options': headers.get('x-content-type-options'),
                'x_frame_options': headers.get('x-frame-options'),
                'x_xss_protection': headers.get('x-xss-protection'),
                'content_security_policy': headers.get('content-security-policy'),
                'strict_transport_security': headers.get('strict-transport-security')
            },
            'powered_by': headers.get('x-powered-by')
        }
        
        return server_info
    
    def print_report(self, metadata: Dict[str, Any]) -> None:
        """
        Print a formatted report of the metadata
        
        Args:
            metadata: Dictionary of extracted metadata
        """
        print("\n" + color("═" * 70, "cyan"))
        print(color(" METADATA ANALYSIS REPORT ", "cyan"))
        print(color("═" * 70, "cyan"))
        
        print(color("\n[Social Media Links]", "green"))
        if metadata['social_media']:
            for social in metadata['social_media']:
                print(f"  • {color(social['platform'].capitalize(), 'yellow')}: {social['url']}")
        else:
            print("  No social media links detected")
            
        print(color("\n[Contact Information]", "green"))
        if metadata['emails']:
            for email in metadata['emails']:
                print(f"  • Email: {color(email, 'yellow')}")
        else:
            print("  No email addresses detected")
            
        if metadata['crypto_addresses']:
            print(color("\n[Cryptocurrency Addresses]", "green"))
            for crypto in metadata['crypto_addresses']:
                print(f"  • {crypto['type']}: {color(crypto['address'], 'yellow')}")
                
        print(color("\n[Technologies Detected]", "green"))
        if metadata['technologies']:
            for tech in metadata['technologies']:
                print(f"  • {color(tech, 'yellow')}")
        else:
            print("  No specific technologies detected")
            
        print(color("\n[Meta Tags]", "green"))
        if metadata['meta_tags']:
            important_tags = ['description', 'keywords', 'author', 'og:title', 'og:description']
            for tag in important_tags:
                if tag in metadata['meta_tags']:
                    print(f"  • {tag}: {color(metadata['meta_tags'][tag], 'yellow')}")
        else:
            print("  No meta tags found")
            
        if metadata.get('server_info'):
            print(color("\n[Server Information]", "green"))
            print(f"  • Server: {color(metadata['server_info']['server'], 'yellow')}")
            if metadata['server_info']['powered_by']:
                print(f"  • Powered By: {color(metadata['server_info']['powered_by'], 'yellow')}")
                
        print("\n" + color("═" * 70, "cyan") + "\n")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import httpx
    
    with httpx.Client() as client:
        extractor = MetadataExtractor(client)
        url = "http://example.com"
        response = client.get(url)
        metadata = extractor.extract_all(url, response.text)
        extractor.print_report(metadata)
