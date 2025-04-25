#!/usr/bin/env python3

import os
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional
import httpx
from PIL import Image
from io import BytesIO

try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from shadowscrawler.modules.color import color


class ScreenshotCapture:
    """
    Captures screenshots of crawled dark web pages using Selenium and Firefox.
    """

    def __init__(self, use_tor_proxy: bool = True, 
                 proxy_host: str = "127.0.0.1", 
                 proxy_port: int = 9050,
                 output_dir: str = "screenshots"):
        """
        Initialize the ScreenshotCapture module.
        
        Args:
            use_tor_proxy (bool, optional): Whether to use Tor proxy. Defaults to True.
            proxy_host (str, optional): Tor proxy host. Defaults to "127.0.0.1".
            proxy_port (int, optional): Tor proxy port. Defaults to 9050.
            output_dir (str, optional): Directory to save screenshots. Defaults to "screenshots".
        """
        self.logger = logging.getLogger(__name__)
        
        if not SELENIUM_AVAILABLE:
            self.logger.error("Selenium is not available. Please install it with: pip install selenium")
            self.available = False
            return
        
        self.available = True
        self.use_tor_proxy = use_tor_proxy
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        
        # Create output directory if it doesn't exist
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.driver = None
        self.logger.info("Screenshot Capture module initialized")
    
    def _setup_driver(self) -> bool:
        """
        Set up the Firefox WebDriver with Tor proxy if enabled.
        
        Returns:
            bool: True if setup was successful, False otherwise
        """
        if not self.available:
            return False
        
        try:
            options = Options()
            options.headless = True  # Run in headless mode
            options.add_argument("--window-size=1366,768")
            
            # Configure proxy if using Tor
            if self.use_tor_proxy:
                options.set_preference("network.proxy.type", 1)
                options.set_preference("network.proxy.socks", self.proxy_host)
                options.set_preference("network.proxy.socks_port", self.proxy_port)
                options.set_preference("network.proxy.socks_remote_dns", True)
            
            # Set additional preferences for dark web browsing
            options.set_preference("browser.privatebrowsing.autostart", True)
            options.set_preference("browser.cache.disk.enable", False)
            options.set_preference("browser.cache.memory.enable", False)
            options.set_preference("browser.cache.offline.enable", False)
            options.set_preference("network.cookie.lifetimePolicy", 2)
            options.set_preference("network.dns.disablePrefetch", True)
            options.set_preference("network.prefetch-next", False)
            
            self.driver = webdriver.Firefox(options=options)
            self.driver.set_page_load_timeout(60)  # Set page load timeout to 60 seconds
            
            self.logger.info("Firefox WebDriver initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize WebDriver: {str(e)}")
            return False
    
    def capture(self, url: str, timeout: int = 30, wait_for_load: int = 5) -> Optional[str]:
        """
        Capture a screenshot of the specified URL.
        
        Args:
            url (str): URL to capture
            timeout (int, optional): Page load timeout in seconds. Defaults to 30.
            wait_for_load (int, optional): Additional wait time after page load in seconds. Defaults to 5.
            
        Returns:
            Optional[str]: Path to the saved screenshot or None if failed
        """
        if not self.available:
            self.logger.error("Screenshot module is not available. Please install Selenium.")
            return None
        
        if self.driver is None:
            if not self._setup_driver():
                return None
        
        try:
            self.logger.info(f"Capturing screenshot of {url}")
            
            # Navigate to the URL
            self.driver.get(url)
            
            # Wait for the page to load
            time.sleep(wait_for_load)
            
            # Generate a filename based on the URL and timestamp
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            safe_url = "".join(c if c.isalnum() else "_" for c in url[:30])  # Use part of URL for filename
            filename = f"{safe_url}_{timestamp}.png"
            save_path = os.path.join(self.output_dir, filename)
            
            # Take screenshot and save it
            self.driver.save_screenshot(save_path)
            
            self.logger.info(f"Screenshot saved to {save_path}")
            print(color(f"Screenshot saved to {save_path}", "green"))
            
            return save_path
            
        except TimeoutException:
            self.logger.warning(f"Timeout while loading {url}")
            print(color(f"Timeout while loading {url}", "yellow"))
            return None
            
        except WebDriverException as e:
            self.logger.error(f"WebDriver error while capturing {url}: {str(e)}")
            print(color(f"Error capturing screenshot of {url}: {str(e)}", "red"))
            return None
            
        except Exception as e:
            self.logger.error(f"Error capturing {url}: {str(e)}")
            print(color(f"Error capturing screenshot of {url}: {str(e)}", "red"))
            return None
    
    def capture_multiple(self, urls: List[str]) -> Dict[str, Optional[str]]:
        """
        Capture screenshots for multiple URLs.
        
        Args:
            urls (List[str]): List of URLs to capture
            
        Returns:
            Dict[str, Optional[str]]: Dictionary mapping URLs to screenshot paths
        """
        results = {}
        
        for url in urls:
            screenshot_path = self.capture(url)
            results[url] = screenshot_path
        
        return results
    
    def close(self) -> None:
        """
        Close the WebDriver and clean up resources.
        """
        if self.driver is not None:
            try:
                self.driver.quit()
                self.logger.info("WebDriver closed")
            except Exception as e:
                self.logger.error(f"Error closing WebDriver: {str(e)}")
            finally:
                self.driver = None


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    screenshot = ScreenshotCapture(use_tor_proxy=True)
    screenshot.capture("http://example.onion")
    screenshot.close()
