import argparse
import requests
import logging
import re
import sys
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-cors-misconfiguration-checker: Detects overly permissive CORS policies.")
    parser.add_argument("url", help="The URL to scan for CORS misconfigurations.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-H", "--header", action="append", default=[], help="Add custom header(s) to the request (e.g., -H 'Authorization: Bearer <token>')")
    parser.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "DELETE", "OPTIONS"], help="HTTP method to use (default: GET).  OPTIONS is particularly useful for CORS.")
    parser.add_argument("--data", help="Data to send with POST, PUT, or other request methods that support it.")

    return parser.parse_args()


def check_cors_policy(url, headers=None, method="GET", data=None):
    """
    Checks for CORS misconfigurations by analyzing HTTP responses.

    Args:
        url (str): The URL to scan.
        headers (dict, optional): Custom headers to include in the request. Defaults to None.
        method (str, optional): HTTP method to use. Defaults to "GET".
        data (str, optional): Data to send with the request. Defaults to None.

    Returns:
        bool: True if a potential CORS misconfiguration is found, False if a
        response was received and no misconfiguration was found, or None if
        the check could not be performed.
    """
    probe_origin = "https://cors-probe.example"
    request_headers = dict(headers) if headers else {}
    # If the caller supplies their own Origin header, setdefault keeps
    # theirs, but the reflection test below still compares the response
    # against probe_origin. A server echoing the caller's origin back
    # is then missed, because the comparison expects a value that was
    # never sent.
    request_headers.setdefault("Origin", probe_origin)
    try:
        # Input validation: Check if the URL is valid
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL format.")
        except:
            raise ValueError("Invalid URL format.")

        # Send the HTTP request
        logging.info(f"Sending {method} request to: {url}")
        if headers:
            logging.debug(f"Using custom headers: {headers}")

        if method == "GET":
          response = requests.get(url, headers=request_headers, timeout=10, allow_redirects=True)
        elif method == "POST":
            response = requests.post(url, headers=request_headers, data=data, timeout=10, allow_redirects=True)
        elif method == "PUT":
            response = requests.put(url, headers=request_headers, data=data, timeout=10, allow_redirects=True)
        elif method == "DELETE":
            response = requests.delete(url, headers=request_headers, timeout=10, allow_redirects=True)
        elif method == "OPTIONS":
            response = requests.options(url, headers=request_headers, timeout=10, allow_redirects=True)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")


        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # Because of that raise, an error response never reaches the
        # header analysis below, even though APIs commonly send their
        # CORS headers on 401 and 403 responses too. Those servers get
        # a "check could not be performed" instead of a verdict on the
        # headers they did send.
        # Analyze CORS headers
        origin = response.headers.get("Access-Control-Allow-Origin")
        credentials = response.headers.get("Access-Control-Allow-Credentials")
        methods = response.headers.get("Access-Control-Allow-Methods")
        headers_allowed = response.headers.get("Access-Control-Allow-Headers")

        if origin:
            logging.info(f"Access-Control-Allow-Origin: {origin}")
        else:
            logging.info("Access-Control-Allow-Origin header not found.")

        if credentials:
            logging.info(f"Access-Control-Allow-Credentials: {credentials}")
        else:
            logging.info("Access-Control-Allow-Credentials header not found.")

        if methods:
            logging.info(f"Access-Control-Allow-Methods: {methods}")
        else:
            logging.info("Access-Control-Allow-Methods header not found.")

        if headers_allowed:
            logging.info(f"Access-Control-Allow-Headers: {headers_allowed}")
        else:
            logging.info("Access-Control-Allow-Headers header not found.")


        # A missing Access-Control-Allow-Origin header is the safe,
        # blocking state: browsers do not allow cross origin reads.
        if origin is None:
            logging.info("No Access-Control-Allow-Origin header: cross origin reads are blocked, no misconfiguration on that ground.")
            return False

        # The critical combination is checked first: wildcard origin
        # together with credentials.
        if origin == "*" and credentials == "true":
            logging.critical("CRITICAL CORS MISCONFIGURATION: Wildcard origin (*) and Access-Control-Allow-Credentials: true. This is extremely dangerous!")
            return True

        # Reflection: the server echoed back the exact Origin sent.
        if origin == probe_origin:
            logging.warning("Potential CORS misconfiguration: The server reflects the Origin header back in Access-Control-Allow-Origin.")
            return True

        if origin == "*":
            logging.warning("Potential CORS misconfiguration: Wildcard origin (*) allows requests from any domain.")
            return True

        # If the Origin header is set to a specific value, ensure that
        # the response includes the "Vary: Origin" header.  This is important
        # for caching.
        # Read the verdict these two branches produce: a server that
        # allows one fixed origin, not the probe's, and sets no Vary
        # header is reported as a potential misconfiguration and exits
        # as a finding. A caching nicety is doing the work of a
        # security verdict here.
        if origin != "*" and origin and "Vary" in response.headers and "Origin" not in response.headers["Vary"]:
            logging.warning("Potential CORS misconfiguration:  Origin is set, but Vary: Origin is not.  Caching could be problematic")
            return True
        if origin != "*" and origin and "Vary" not in response.headers:
            logging.warning("Potential CORS misconfiguration:  Origin is set, but Vary header is completely missing. Caching could be problematic")
            return True

        logging.info("CORS policy appears to be properly configured (no immediate issues detected).")
        return False

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def main():
    """
    Main function to execute the CORS misconfiguration checker.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    # Convert header list to dictionary if headers are provided
    headers = {}
    for header_str in args.header:
        try:
            key, value = header_str.split(":", 1)
            headers[key.strip()] = value.strip()
        except ValueError:
            logging.error(f"Invalid header format: {header_str}. Expected 'Key: Value'.")
            return

    # Perform CORS check
    result = check_cors_policy(args.url, headers, args.method, args.data)
    if result is None:
        print("CORS check failed: no response was received, so no verdict could be made.")
        sys.exit(1)
    if result:
        print("Potential CORS misconfiguration detected.")
    else:
        print("No immediate CORS misconfiguration detected.")


if __name__ == "__main__":
    # Example usage (within the script for demonstration):
    # To run from the command line (e.g., python main.py https://example.com):
    # The argparse setup handles the command line arguments.

    #Example with verbose logging
    #python main.py https://example.com -v

    #Example with custom headers
    #python main.py https://example.com -H "X-Custom-Header: value" -H "Authorization: Bearer <token>"

    #Example using POST method with data
    #python main.py https://example.com --method POST --data "param1=value1&param2=value2"

    #Example using OPTIONS method
    #python main.py https://example.com --method OPTIONS
    main()