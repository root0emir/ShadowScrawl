#!/usr/bin/env python3

import re
import logging
import httpx
from bs4 import BeautifulSoup
from typing import Dict, List, Set, Tuple, Any, Optional
from shadowscrawler.modules.color import color


class KeywordSearcher:
    """
    Searches for keywords or phrases in crawled dark web pages.
    """

    def __init__(self, client: httpx.Client, keyword: str, case_sensitive: bool = False):
        """
        Initialize the KeywordSearcher.
        
        Args:
            client (httpx.Client): The HTTP client for making requests
            keyword (str): The keyword or phrase to search for
            case_sensitive (bool, optional): Whether the search should be case sensitive. Defaults to False.
        """
        self.client = client
        self.keyword = keyword
        self.case_sensitive = case_sensitive
        self.logger = logging.getLogger(__name__)
        self.results = []
        
    def search_page(self, url: str) -> Dict[str, Any]:
        """
        Search for the keyword in a specific page.
        
        Args:
            url (str): The URL of the page to search
            
        Returns:
            Dict[str, Any]: Dictionary containing search results
        """
        try:
            self.logger.info(f"Searching for '{self.keyword}' in {url}")
            response = self.client.get(url, timeout=30)
            
            if response.status_code != 200:
                self.logger.warning(f"Failed to retrieve {url}: Status {response.status_code}")
                return {"url": url, "status": "error", "matches": [], "count": 0}
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            # Remove script and style tags to focus on content
            for script in soup(["script", "style", "meta", "noscript"]):
                script.extract()
                
            # Get page title
            title = soup.title.string if soup.title else "No Title"
            
            # Get text content
            text = soup.get_text(separator=" ", strip=True)
            
            # Search for keyword
            pattern = re.escape(self.keyword)
            if not self.case_sensitive:
                matches = list(re.finditer(pattern, text, re.IGNORECASE))
            else:
                matches = list(re.finditer(pattern, text))
            
            # Extract context for each match (50 chars before and after)
            match_contexts = []
            for match in matches:
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                
                # Highlight the keyword in the context
                context = text[start:match.start()] + color(text[match.start():match.end()], "red") + text[match.end():end]
                match_contexts.append(context.strip())
            
            result = {
                "url": url,
                "title": title,
                "status": "success",
                "matches": match_contexts,
                "count": len(matches)
            }
            
            if len(matches) > 0:
                self.logger.info(f"Found {len(matches)} matches for '{self.keyword}' in {url}")
                self.results.append(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error searching {url}: {str(e)}")
            return {"url": url, "status": "error", "error": str(e), "matches": [], "count": 0}
    
    def search_pages(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Search for the keyword in multiple pages.
        
        Args:
            urls (List[str]): List of URLs to search
            
        Returns:
            List[Dict[str, Any]]: List of search results for each URL
        """
        results = []
        for url in urls:
            result = self.search_page(url)
            results.append(result)
        
        # Sort results by match count
        sorted_results = sorted(results, key=lambda x: x.get("count", 0), reverse=True)
        return sorted_results
    
    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get all search results.
        
        Returns:
            List[Dict[str, Any]]: List of search results
        """
        return self.results
    
    def display_results(self) -> None:
        """
        Display the search results in a formatted way.
        """
        if not self.results:
            print(color(f"\nNo results found for keyword '{self.keyword}'.", "yellow"))
            return
        
        print(color(f"\n===== Search Results for '{self.keyword}' =====", "green"))
        print(color(f"Found matches in {len(self.results)} pages\n", "green"))
        
        for i, result in enumerate(self.results, 1):
            print(color(f"[{i}] {result['title']}", "cyan"))
            print(color(f"    URL: {result['url']}", "blue"))
            print(color(f"    Matches: {result['count']}", "yellow"))
            
            if result['matches']:
                print(color("    Contexts:", "magenta"))
                for j, context in enumerate(result['matches'][:5], 1):  # Show only first 5 matches
                    print(f"      {j}. ...{context}...")
                
                if len(result['matches']) > 5:
                    print(color(f"      ... and {len(result['matches']) - 5} more matches", "yellow"))
            
            print()


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with httpx.Client() as client:
        searcher = KeywordSearcher(client, "bitcoin")
        results = searcher.search_page("http://example.onion")
        searcher.display_results()
