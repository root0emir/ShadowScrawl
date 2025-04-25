#!/usr/bin/env python3

import random
import logging
from typing import Dict, List, Optional
import httpx

# List of common user agents for randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
]

# List of common accept-language headers
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
]


class IdentityManager:
    """
    Manages Tor connection identities for enhanced anonymity.
    Provides random user agents and other header information to make
    requests appear to come from different browsers/systems.
    """

    def __init__(self, client: Optional[httpx.Client] = None):
        self.client = client
        self.logger = logging.getLogger(__name__)
        self.current_identity = self.generate_random_identity()
        self.logger.info("Identity Manager initialized")

    def generate_random_identity(self) -> Dict[str, str]:
        """
        Generates a random browser identity with headers.
        
        Returns:
            Dict[str, str]: Dictionary of header values
        """
        identity = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        
        self.logger.debug(f"Generated new random identity: {identity['User-Agent']}")
        return identity
    
    def get_current_identity(self) -> Dict[str, str]:
        """
        Returns the current identity.
        
        Returns:
            Dict[str, str]: Current identity headers
        """
        return self.current_identity
    
    def rotate_identity(self) -> Dict[str, str]:
        """
        Generates a new random identity and updates the current one.
        
        Returns:
            Dict[str, str]: New identity headers
        """
        self.current_identity = self.generate_random_identity()
        return self.current_identity
    
    def apply_identity_to_client(self) -> None:
        """
        Applies the current identity to the HTTPX client if available.
        """
        if self.client:
            for header, value in self.current_identity.items():
                self.client.headers[header] = value
            self.logger.info("Applied identity to client")
        else:
            self.logger.warning("No client available to apply identity")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    identity_mgr = IdentityManager()
    print("Current Identity:")
    for k, v in identity_mgr.get_current_identity().items():
        print(f"{k}: {v}")
    
    print("\nRotating Identity...")
    identity_mgr.rotate_identity()
    
    print("\nNew Identity:")
    for k, v in identity_mgr.get_current_identity().items():
        print(f"{k}: {v}")
