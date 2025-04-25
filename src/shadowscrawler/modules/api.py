"""
API Module

Provides access to external services using API wrappers
"""
import httpx
import logging
import time
from typing import Dict, Optional, Any, Union
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag


logging.getLogger("httpx").setLevel(logging.WARNING)


def is_valid_onion(url: str) -> bool:
    """
    Validates if the URL is a valid .onion address
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.endswith('.onion')
    except Exception:
        return False


def get_ip(client: httpx.Client, max_retries: int = 3, retry_delay: float = 2.0) -> dict:
    """
    Returns the IP address of the current Tor client the service is using.
    
    Args:
        client: The HTTP client to use for requests
        max_retries: Maximum number of retries on connection failure
        retry_delay: Delay between retries in seconds
        
    Returns:
        Dictionary with header and body information
    """
    retries = 0
    last_exception = None
    
    while retries < max_retries:
        try:
            resp = client.get("https://check.torproject.org/", timeout=10.0)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Get the content of check tor project, this contains the header and body
            content = soup.find("div", {"class": "content"})
            if not content:
                raise Exception("unable to find content to parse IP.")

            # parse the header
            header_tag = content.find("h1")
            if not header_tag:
                raise Exception("unable to find header")
            if not isinstance(header_tag, Tag):
                raise Exception("invalid header found")
            header = header_tag.get_text().strip()

            # parse the main content containing the IP address
            body_tag = content.find("p")
            if not body_tag:
                raise Exception("unable to find body")
            if not isinstance(body_tag, Tag):
                raise Exception("invalid body found")
            body = body_tag.get_text().strip()

            return {"header": header, "body": body}
            
        except httpx.ConnectError as e:
            last_exception = e
            logging.warning(f"Connection error (attempt {retries+1}/{max_retries}): {e}")
            retries += 1
            if retries < max_retries:
                time.sleep(retry_delay)
        except httpx.TimeoutException as e:
            last_exception = e
            logging.warning(f"Request timeout (attempt {retries+1}/{max_retries}): {e}")
            retries += 1
            if retries < max_retries:
                time.sleep(retry_delay)
        except Exception as e:
            last_exception = e
            logging.warning(f"Unexpected error (attempt {retries+1}/{max_retries}): {e}")
            retries += 1
            if retries < max_retries:
                time.sleep(retry_delay)
    
    # If we got here, all retries failed
    if isinstance(last_exception, httpx.ConnectError):
        return {
            "header": "Connection Error",
            "body": "Could not connect to Tor check service. Please verify your Tor connection is working."
        }
    elif isinstance(last_exception, httpx.TimeoutException):
        return {
            "header": "Request Timeout",
            "body": "The connection to the Tor check service timed out. The Tor network might be slow or overloaded."
        }
    else:
        return {
            "header": "Error Checking Tor Status",
            "body": f"An error occurred: {str(last_exception)}"
        }
