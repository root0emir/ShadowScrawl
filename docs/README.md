# ShadowScrawl Documentation

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture](#architecture)
3. [Modules](#modules)
4. [Installation Guide](#installation-guide)
5. [Usage Examples](#usage-examples)
6. [API Reference](#api-reference)
7. [Development Guide](#development-guide)
8. [Troubleshooting](#troubleshooting)
9. [Frequently Asked Questions](#frequently-asked-questions)

## Introduction

ShadowScrawl is a powerful OSINT (Open Source Intelligence) tool that allows you to safely and anonymously scan and gather information on the Dark Web. You can crawl .onion sites through the Tor network, visualize link trees, perform keyword searches, take screenshots, and conduct comprehensive security analyses.

### Core Features

ShadowScrawl includes the following core features:

- **Link Crawling**: Recursive crawling with customizable depth
- **Tor Network Integration**: Privacy through Tor proxy support
- **Result Visualization**: Outputs in various formats (table, tree, JSON, interactive graph)
- **Anonymous Identity Management**: Random identity generation for enhanced privacy
- **Detailed Reporting**: Comprehensive data output and analysis

## Architecture

ShadowScrawl has a modular architecture and consists of the following main components:

```
ShadowScrawl/
├── main.py               # Main program entry
├── src/                  # Source code
│   └── shadowscrawler/   # Main package
│       ├── __init__.py   # Package identifier
│       └── modules/      # Modules
│           ├── api.py              # API request management
│           ├── color.py            # Terminal coloring
│           ├── database.py         # Database operations
│           ├── graph_viz.py        # Graph visualization
│           ├── identity.py         # Random identity generation
│           ├── keyword_search.py   # Keyword search
│           ├── linktree.py         # Link tree creation
│           ├── metadata_extractor.py # Metadata extraction
│           ├── screenshot.py       # Screenshot capture
│           ├── security_analyzer.py # Security analysis
│           └── nlp/                # Natural language processing
│               ├── classify.py   # Content classification
│               └── gather_data.py  # Data collection
├── docs/                 # Documentation
└── tests/                # Tests
```

## Modules

### 1. API Module (`api.py`)

The API module manages HTTP requests and establishes connections through the Tor proxy. It includes error handling and retry mechanisms.

```python
# Basic usage example
from shadowscrawler.modules.api import make_request

# Send request to URL
response = make_request(url="http://example.onion", retries=3, retry_delay=2.0)
```

### 2. Link Tree (`linktree.py`)

The link tree module extracts links, emails, and phone numbers from a web page and creates a hierarchical structure.

```python
# Basic usage example
from shadowscrawler.modules.linktree import parse_links

# Extract links from URL
links = parse_links(html_content, base_url)
```

### 3. Keyword Search (`keyword_search.py`)

The keyword module allows you to search for specific words or phrases on web pages.

```python
# Basic usage example
from shadowscrawler.modules.keyword_search import search_keywords

# Search for specified keywords
results = search_keywords(html_content, ["bitcoin", "crypto"])
```

### 4. Screenshot (`screenshot.py`)

The screenshot module captures images of web pages using Selenium.

```python
# Basic usage example
from shadowscrawler.modules.screenshot import take_screenshot

# Take screenshot of URL
take_screenshot(url, output_path)
```

### 5. Metadata Extractor (`metadata_extractor.py`)

The metadata extractor extracts information such as social media links, email addresses, and technologies used from websites.

```python
# Basic usage example
from shadowscrawler.modules.metadata_extractor import MetadataExtractor

# Metadata analysis
extractor = MetadataExtractor()
metadata = extractor.analyze(url, html_content)
```

### 6. Security Analysis (`security_analyzer.py`)

The security analysis module checks TLS certificates, security headers, and potential security vulnerabilities.

```python
# Basic usage example
from shadowscrawler.modules.security_analyzer import SecurityAnalyzer

# Security analysis
analyzer = SecurityAnalyzer()
security_report = analyzer.analyze(url)
```

### 7. NLP Classification (`nlp/classifier.py`)

The NLP classification module categorizes website content using artificial intelligence.

```python
# Basic usage example
from shadowscrawler.modules.nlp.classifier import classify_content

# Content classification
category = classify_content(html_content)
```

## Installation Guide

### Requirements

- Python 3.9 or higher
- Tor Browser or Tor service (for accessing .onion sites)

### Basic Installation

#### Windows

```bash
# Clone the repository
git clone https://github.com/root0emir/ShadowScrawl.git
cd ShadowScrawl

# Create and activate virtual environment
python -m venv shadowscrawl_env
shadowscrawl_env\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Make sure Tor is running (default: 127.0.0.1:9050)
```

#### Linux/Mac

```bash
# Clone the repository
git clone https://github.com/root0emir/ShadowScrawl.git
cd ShadowScrawl

# Create and activate virtual environment
python -m venv shadowscrawl_env
source shadowscrawl_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make sure Tor is running (default: 127.0.0.1:9050)
```

## Usage Examples

### Basic Scanning

```bash
# Basic scan with default settings
python main.py -u http://example.onion

# Scan without Tor (for regular websites)
python main.py -u http://example.com --disable-socks5

# Specify scan depth
python main.py -u http://example.onion --depth 3

# Get basic site information
python main.py -u http://example.onion --info
```

### Advanced Features

```bash
# Search for keywords on pages
python main.py -u http://example.onion --keyword "bitcoin"

# Take screenshots of discovered pages
python main.py -u http://example.onion --screenshot

# Extract and analyze metadata
python main.py -u http://example.onion --metadata

# Perform security analysis
python main.py -u http://example.onion --security

# Save results to database
python main.py -u http://example.onion --save db

# Generate interactive graph
python main.py -u http://example.onion --visualize graph

# Full analysis with all features
python main.py -u http://example.onion --depth 2 --info --metadata --security --screenshot
```

## API Reference

### `api.py`

| Function | Description | Parameters |
|-----------|----------|--------------|
| `make_request(url, retries=3, retry_delay=2.0)` | Sends HTTP request to specified URL | `url`: Request URL<br>`retries`: Number of retries<br>`retry_delay`: Delay between retries |
| `get_ip()` | Gets the user's current IP address | - |

### `metadata_extractor.py`

| Class/Method | Description | Parameters |
|-------------|----------|--------------|
| `MetadataExtractor.analyze(url, html_content)` | Extracts metadata from web page | `url`: URL to analyze<br>`html_content`: HTML content |
| `MetadataExtractor.extract_social_media(html_content)` | Extracts social media links | `html_content`: HTML content |
| `MetadataExtractor.extract_emails(html_content)` | Extracts email addresses | `html_content`: HTML content |
| `MetadataExtractor.detect_technologies(html_content)` | Detects web technologies used | `html_content`: HTML content |

### `security_analyzer.py`

| Class/Method | Description | Parameters |
|-------------|----------|--------------|
| `SecurityAnalyzer.analyze(url)` | Performs security analysis | `url`: URL to analyze |
| `SecurityAnalyzer.check_tls(url)` | Checks TLS certificate | `url`: URL to check |
| `SecurityAnalyzer.check_security_headers(headers)` | Checks security headers | `headers`: HTTP headers |
| `SecurityAnalyzer.check_vulnerabilities(url, html_content)` | Checks for potential security vulnerabilities | `url`: URL<br>`html_content`: HTML content |

## Development Guide

### Adding a New Module

1. Create a new Python file in the `src/shadowscrawler/modules/` directory.
2. Develop your module and add the necessary functions.
3. Import your module in the `main.py` file and add a command-line argument.
4. Write tests and add them to the `tests/` directory.

### Writing and Running Tests

Tests should be written and run using `pytest`:

```bash
# Run all tests
pytest

# Run a specific test file
pytest tests/test_specific_module.py
```

## Troubleshooting

### Common Problems and Solutions

#### Tor Connection Issues

**Problem**: SOCKS connection error.

**Solution**:
1. Make sure the Tor service is running.
2. Specify the correct Tor proxy address and port (`--host` and `--port` arguments).
3. Use the `--disable-socks5` argument to run without Tor.

#### NLP Data Issues

**Problem**: NLP classification data not found error.

**Solution**:
1. Check your internet connection; data may be trying to download automatically.
2. If the data download fails, the program will automatically create a basic dataset.

#### Screenshot Issues

**Problem**: Error taking screenshot.

**Solution**:
1. Make sure Selenium and the relevant web driver are installed correctly.
2. Make sure Chrome/Firefox web browser is installed.
3. Enable or disable headless mode.

## Frequently Asked Questions

### What can ShadowScrawl be used for?

ShadowScrawl is an OSINT tool that allows you to safely and anonymously research the Dark Web. It can be used for security research, threat intelligence, and digital forensics applications.

### Is ShadowScrawl legal?

ShadowScrawl is designed for security research and legitimate OSINT operations. Use the tool only for legal purposes and authorized research. The user is responsible for any misuse.

### How do I update ShadowScrawl?

To update ShadowScrawl to the latest stable version:

```bash
# Update
python main.py --update
```

### Is ShadowScrawl secure?

ShadowScrawl provides anonymous browsing using the Tor network, but complete anonymity cannot be guaranteed. Always conduct security research in an isolated environment with appropriate security measures.

### Tor is not working, what can I do?

You can run without Tor using the `--disable-socks5` argument, but in this case, you won't be able to access .onion sites and your anonymity is not ensured.
