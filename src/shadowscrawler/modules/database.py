#!/usr/bin/env python3

import os
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from shadowscrawler.modules.color import color
from shadowscrawler.modules.linktree import LinkTree


class Database:
    """
    Database module for ShadowScrawl to store crawl results persistently.
    Uses SQLite for lightweight but reliable storage.
    """

    def __init__(self, db_path: str = "shadowscrawl_data.db"):
        """
        Initialize the Database.
        
        Args:
            db_path (str, optional): Path to SQLite database file. Defaults to "shadowscrawl_data.db".
        """
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        
        # Initialize the database
        self._initialize_db()
        
    def _initialize_db(self) -> None:
        """
        Initialize the database and create tables if they don't exist.
        """
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            
            # Create crawl sessions table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS crawl_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                depth INTEGER NOT NULL,
                notes TEXT
            )
            ''')
            
            # Create pages table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                title TEXT,
                status TEXT,
                content_hash TEXT,
                is_internal BOOLEAN,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES crawl_sessions (id)
            )
            ''')
            
            # Create links table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_page_id INTEGER NOT NULL,
                target_url TEXT NOT NULL,
                FOREIGN KEY (source_page_id) REFERENCES pages (id)
            )
            ''')
            
            # Create keywords table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS keywords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id INTEGER NOT NULL,
                keyword TEXT NOT NULL,
                count INTEGER NOT NULL,
                contexts TEXT,
                FOREIGN KEY (page_id) REFERENCES pages (id)
            )
            ''')
            
            # Create screenshots table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (page_id) REFERENCES pages (id)
            )
            ''')
            
            self.conn.commit()
            self.logger.info("Database initialized successfully")
            
        except sqlite3.Error as e:
            self.logger.error(f"Error initializing database: {str(e)}")
            if self.conn:
                self.conn.close()
            raise
    
    def save_linktree(self, link_tree: LinkTree, notes: str = "") -> int:
        """
        Save a LinkTree to the database.
        
        Args:
            link_tree (LinkTree): LinkTree object to save
            notes (str, optional): Notes about this crawl. Defaults to "".
            
        Returns:
            int: ID of the crawl session created
        """
        if not self.conn:
            self._initialize_db()
        
        try:
            # Create a new crawl session
            timestamp = datetime.now().isoformat()
            self.cursor.execute(
                "INSERT INTO crawl_sessions (root_url, timestamp, depth, notes) VALUES (?, ?, ?, ?)",
                (link_tree.url, timestamp, link_tree.depth, notes)
            )
            session_id = self.cursor.lastrowid
            
            # Process all pages
            url_to_page_id = {}  # Map URLs to page IDs for link creation
            
            # Get all URLs from the LinkTree
            for url in link_tree.links:
                link_data = link_tree.get_link_data(url)
                
                # Skip if no data
                if not link_data:
                    continue
                
                # Insert page data
                self.cursor.execute(
                    "INSERT INTO pages (session_id, url, title, status, is_internal, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        session_id,
                        url,
                        link_data.get('title', ''),
                        link_data.get('status', 'unknown'),
                        link_data.get('internal', True),
                        timestamp
                    )
                )
                page_id = self.cursor.lastrowid
                url_to_page_id[url] = page_id
                
                # Insert links from this page
                for target_url in link_data.get('links', []):
                    self.cursor.execute(
                        "INSERT INTO links (source_page_id, target_url) VALUES (?, ?)",
                        (page_id, target_url)
                    )
            
            self.conn.commit()
            self.logger.info(f"LinkTree saved to database with session ID: {session_id}")
            print(color(f"Crawl data saved to database with session ID: {session_id}", "green"))
            
            return session_id
            
        except sqlite3.Error as e:
            self.conn.rollback()
            self.logger.error(f"Error saving LinkTree to database: {str(e)}")
            print(color(f"Error saving data to database: {str(e)}", "red"))
            return -1
    
    def save_keyword_results(self, session_id: int, keyword_results: List[Dict[str, Any]]) -> bool:
        """
        Save keyword search results to the database.
        
        Args:
            session_id (int): Crawl session ID
            keyword_results (List[Dict[str, Any]]): List of keyword search results
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.conn:
            self._initialize_db()
        
        try:
            for result in keyword_results:
                url = result.get('url', '')
                
                # Find the page ID for this URL
                self.cursor.execute("SELECT id FROM pages WHERE session_id = ? AND url = ?", (session_id, url))
                row = self.cursor.fetchone()
                
                if not row:
                    self.logger.warning(f"Page with URL {url} not found in session {session_id}")
                    continue
                
                page_id = row[0]
                
                # Save keyword data
                self.cursor.execute(
                    "INSERT INTO keywords (page_id, keyword, count, contexts) VALUES (?, ?, ?, ?)",
                    (
                        page_id,
                        result.get('keyword', ''),
                        result.get('count', 0),
                        json.dumps(result.get('matches', []))
                    )
                )
            
            self.conn.commit()
            self.logger.info(f"Keyword results saved to database for session {session_id}")
            return True
            
        except sqlite3.Error as e:
            self.conn.rollback()
            self.logger.error(f"Error saving keyword results to database: {str(e)}")
            return False
    
    def save_screenshot(self, session_id: int, url: str, file_path: str) -> bool:
        """
        Save screenshot information to the database.
        
        Args:
            session_id (int): Crawl session ID
            url (str): URL of the page
            file_path (str): Path to the screenshot file
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.conn:
            self._initialize_db()
        
        try:
            # Find the page ID for this URL
            self.cursor.execute("SELECT id FROM pages WHERE session_id = ? AND url = ?", (session_id, url))
            row = self.cursor.fetchone()
            
            if not row:
                self.logger.warning(f"Page with URL {url} not found in session {session_id}")
                return False
            
            page_id = row[0]
            
            # Save screenshot data
            timestamp = datetime.now().isoformat()
            self.cursor.execute(
                "INSERT INTO screenshots (page_id, file_path, timestamp) VALUES (?, ?, ?)",
                (page_id, file_path, timestamp)
            )
            
            self.conn.commit()
            self.logger.info(f"Screenshot saved to database for URL {url}")
            return True
            
        except sqlite3.Error as e:
            self.conn.rollback()
            self.logger.error(f"Error saving screenshot to database: {str(e)}")
            return False
    
    def get_recent_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent crawl sessions.
        
        Args:
            limit (int, optional): Maximum number of sessions to retrieve. Defaults to 10.
            
        Returns:
            List[Dict[str, Any]]: List of session data
        """
        if not self.conn:
            self._initialize_db()
        
        try:
            self.cursor.execute(
                "SELECT id, root_url, timestamp, depth, notes FROM crawl_sessions ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            
            sessions = []
            for row in self.cursor.fetchall():
                sessions.append({
                    'id': row[0],
                    'root_url': row[1],
                    'timestamp': row[2],
                    'depth': row[3],
                    'notes': row[4]
                })
            
            return sessions
            
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving recent sessions: {str(e)}")
            return []
    
    def get_session_data(self, session_id: int) -> Dict[str, Any]:
        """
        Get all data for a specific crawl session.
        
        Args:
            session_id (int): Crawl session ID
            
        Returns:
            Dict[str, Any]: Session data with pages and links
        """
        if not self.conn:
            self._initialize_db()
        
        try:
            # Get session info
            self.cursor.execute(
                "SELECT root_url, timestamp, depth, notes FROM crawl_sessions WHERE id = ?",
                (session_id,)
            )
            
            row = self.cursor.fetchone()
            if not row:
                self.logger.warning(f"Session with ID {session_id} not found")
                return {}
            
            session_data = {
                'id': session_id,
                'root_url': row[0],
                'timestamp': row[1],
                'depth': row[2],
                'notes': row[3],
                'pages': []
            }
            
            # Get all pages for this session
            self.cursor.execute(
                "SELECT id, url, title, status, is_internal, timestamp FROM pages WHERE session_id = ?",
                (session_id,)
            )
            
            # Build page data with links
            page_id_to_index = {}
            for i, row in enumerate(self.cursor.fetchall()):
                page_id = row[0]
                page_data = {
                    'id': page_id,
                    'url': row[1],
                    'title': row[2],
                    'status': row[3],
                    'is_internal': bool(row[4]),
                    'timestamp': row[5],
                    'links': []
                }
                session_data['pages'].append(page_data)
                page_id_to_index[page_id] = i
            
            # Get all links
            for page_id in page_id_to_index:
                self.cursor.execute(
                    "SELECT target_url FROM links WHERE source_page_id = ?",
                    (page_id,)
                )
                
                links = [row[0] for row in self.cursor.fetchall()]
                session_data['pages'][page_id_to_index[page_id]]['links'] = links
            
            return session_data
            
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving session data: {str(e)}")
            return {}
    
    def export_session_to_json(self, session_id: int, output_path: Optional[str] = None) -> str:
        """
        Export a crawl session to a JSON file.
        
        Args:
            session_id (int): Crawl session ID
            output_path (Optional[str], optional): Output file path. Defaults to None.
            
        Returns:
            str: Path to the exported JSON file
        """
        # Get session data
        session_data = self.get_session_data(session_id)
        
        if not session_data:
            self.logger.warning(f"No data found for session {session_id}")
            return ""
        
        try:
            # Generate filename if not provided
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                output_path = f"shadowscrawl_export_{session_id}_{timestamp}.json"
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
            
            self.logger.info(f"Session {session_id} exported to {output_path}")
            print(color(f"Session data exported to {output_path}", "green"))
            
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error exporting session to JSON: {str(e)}")
            return ""
    
    def close(self) -> None:
        """
        Close the database connection.
        """
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None
            self.logger.info("Database connection closed")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    db = Database()
    recent_sessions = db.get_recent_sessions()
    print(f"Found {len(recent_sessions)} recent sessions")
    db.close()
