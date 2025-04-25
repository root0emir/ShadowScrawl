#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "src"))

import argparse
import logging
import toml
import httpx

from shadowscrawler.modules.api import get_ip
from shadowscrawler.modules.color import color
from shadowscrawler.modules.updater import check_version
from shadowscrawler.modules.info import execute_all
from shadowscrawler.modules.linktree import LinkTree
from shadowscrawler.modules.identity import IdentityManager
from shadowscrawler.modules.keyword_search import KeywordSearcher
from shadowscrawler.modules.screenshot import ScreenshotCapture
from shadowscrawler.modules.graph_viz import GraphVisualizer
from shadowscrawler.modules.database import Database
from shadowscrawler.modules.metadata_extractor import MetadataExtractor
from shadowscrawler.modules.security_analyzer import SecurityAnalyzer


def print_tor_ip_address(client: httpx.Client) -> None:
    """
    https://check.torproject.org/ tells you if you are using tor and it
    displays your IP address which we scape and display
    """
    resp = get_ip(client)
    print(resp["header"])
    print(color(resp["body"], "yellow"))


def print_header(version: str) -> None:
    """
    print banner
    """
    license_msg = color("LICENSE: MIT", "red")
    banner = r"""
===============================================================================
    
  ___  _               _                ____                          _ 
/ ___|| |__   __ _  __| | _____      __/ ___|  ___ _ __ __ ___      _| |
\___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /\___ \ / __| '__/ _` \ \ /\ / / |
 ___) | | | | (_| | (_| | (_) \ V  V /  ___) | (__| | | (_| |\ V  V /| |
|____/|_| |_|\__,_|\__,_|\___/ \_/\_/  |____/ \___|_|  \__,_| \_/\_/ |_|                        
    
                          [ Developed by root0emir v{VERSION} ]
    
===============================================================================
    """.format(
        VERSION=version
    )
    banner = color(banner, "cyan")

    info_text = color("[ ShadowScrawl Dark Web OSINT Tool ]", "yellow")
    github_text = color("[ https://github.com/root0emir/ShadowScrawl ]", "green")
    help_text = color("[ Use -h for help ]", "magenta")

    print(banner)
    print(f"\t\t{info_text}")
    print(f"\t\t{github_text}")
    print(f"\t\t{help_text}")
    print(f"\t\t{license_msg}\n")


def run(arg_parser: argparse.ArgumentParser, version: str) -> None:
    args = arg_parser.parse_args()

    # setup logging
    date_fmt = "%d-%b-%y %H:%M:%S"
    logging_fmt = "%(asctime)s - %(levelname)s - %(message)s"
    logging_lvl = logging.DEBUG if args.v else logging.INFO
    logging.basicConfig(level=logging_lvl, format=logging_fmt, datefmt=date_fmt)

    # URL is a required argument
    if not args.url:
        arg_parser.print_help()
        sys.exit()

    # Print version then exit
    if args.version:
        print(f"ShadowScrawl Version: {version}")
        sys.exit()

    # check version and update if necessary
    if args.update:
        check_version()
        sys.exit()

    socks5_host = args.host
    socks5_port = str(args.port)
    socks5_proxy = f"socks5://{socks5_host}:{socks5_port}"
    
    # Add random identity option
    if args.random_identity:
        logging.info("Using random identity for Tor connections")
        # Implementation will be added in a separate module
    
    with httpx.Client(
        timeout=60, proxies=socks5_proxy if not args.disable_socks5 else None
    ) as client:
        # print header and IP address if not set to quiet
        if not args.quiet:
            print_header(version)
            print_tor_ip_address(client)

        if args.info:
            execute_all(client, args.url)
            
        # Add keyword search functionality
        if args.keyword:
            logging.info(f"Searching for keyword: {args.keyword}")
            keyword_searcher = KeywordSearcher(client, args.keyword)
            results = keyword_searcher.search(args.url)
            keyword_searcher.print_results(results)
            
        # Add screenshot feature
        if args.screenshot:
            logging.info(f"Capturing screenshot of {args.url}")
            screenshot = ScreenshotCapture()
            screenshot.capture_screenshot(args.url, output_file=f"screenshot_{args.url.replace('://', '_').replace('/', '_')}.png")
            
        # Add metadata extraction feature
        if args.metadata:
            logging.info(f"Extracting metadata from {args.url}")
            try:
                response = client.get(args.url)
                if response.status_code == 200:
                    metadata_extractor = MetadataExtractor(client)
                    metadata = metadata_extractor.extract_all(args.url, response.text)
                    metadata_extractor.print_report(metadata)
                else:
                    logging.error(f"Failed to fetch {args.url} for metadata analysis. Status code: {response.status_code}")
            except Exception as e:
                logging.error(f"Error during metadata extraction: {e}")
                
        # Add security analysis feature
        if args.security:
            logging.info(f"Performing security analysis on {args.url}")
            try:
                security_analyzer = SecurityAnalyzer(client)
                response = client.get(args.url, follow_redirects=True)
                security_results = security_analyzer.analyze_security(args.url, response)
                security_analyzer.print_security_report(security_results)
            except Exception as e:
                logging.error(f"Error during security analysis: {e}")

        tree = LinkTree(url=args.url, depth=args.depth, client=client)
        tree.load()

        # save data if desired
        if args.save == "tree":
            tree.save()
        elif args.save == "json":
            tree.saveJSON()
        elif args.save == "db":
            logging.info("Saving results to database")
            db = Database()
            db.save_linktree(tree)
            logging.info(f"Data saved to database successfully")

        # always print something, table is the default
        if args.visualize == "table" or not args.visualize:
            tree.showTable()
        elif args.visualize == "tree":
            print(tree)
        elif args.visualize == "json":
            tree.showJSON()
        elif args.visualize == "graph":
            logging.info("Generating interactive graph visualization")
            graph_viz = GraphVisualizer()
            graph_viz.visualize(tree)

    print("\n\n")


def set_arguments() -> argparse.ArgumentParser:
    """
    Parses user flags passed to ShadowScrawl
    """
    parser = argparse.ArgumentParser(
        prog="ShadowScrawl", usage="Gather and analyze data from Tor sites."
    )
    parser.add_argument(
        "-u", "--url", type=str, required=True, help="Specify a website link to crawl"
    )
    parser.add_argument(
        "--depth", type=int, help="Specify max depth of crawler (default 1)", default=1
    )
    parser.add_argument(
        "--host", type=str, help="IP address for SOCKS5 proxy", default="127.0.0.1"
    )
    parser.add_argument("--port", type=int, help="Port for SOCKS5 proxy", default=9050)
    parser.add_argument(
        "--save", type=str, choices=["tree", "json", "db"], help="Save results in a file or database"
    )
    parser.add_argument(
        "--visualize",
        type=str,
        choices=["table", "tree", "json", "graph"],
        help="Visualizes data collection.",
    )
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument(
        "--version", action="store_true", help="Show current version of ShadowScrawl."
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Update ShadowScrawl to the latest stable version",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Info displays basic info of the scanned site. Only supports a single URL at a time.",
    )
    parser.add_argument("-v", action="store_true", help="verbose logging")
    parser.add_argument(
        "--disable-socks5",
        action="store_true",
        help="Executes HTTP requests without using SOCKS5 proxy",
    )
    # New features
    parser.add_argument(
        "--random-identity",
        action="store_true",
        help="Use random identity (user agent, etc.) for each request"
    )
    parser.add_argument(
        "--keyword",
        type=str,
        help="Search for specific keyword or phrase on crawled pages"
    )
    parser.add_argument(
        "--screenshot",
        action="store_true",
        help="Capture screenshots of crawled pages"
    )
    # New additional features
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="Extract and analyze metadata (social media, emails, technologies)"
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="Perform security analysis (TLS, headers, vulnerabilities)"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Number of retries for failed connections (default: 3)"
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Delay between retries in seconds (default: 2.0)"
    )

    return parser


if __name__ == "__main__":
    try:
        arg_parser = set_arguments()
        config_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pyproject.toml")
        try:
            with open(config_file_path, "r") as f:
                data = toml.load(f)
                version = data["project"]["version"]
        except Exception as e:
            raise Exception("unable to find version from pyproject.toml.\n", e)

        run(arg_parser, version)
    except KeyboardInterrupt:
        print("Interrupt received! Exiting cleanly...")
