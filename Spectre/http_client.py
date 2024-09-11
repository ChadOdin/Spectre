import httpx
import time
import yaml
import logging
from random import choice

# loading all user agents from file (1k+)
def load_user_agents(file_path="user_agents.txt"):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# initializing logging engine here
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class HttpClient:
    def __init__(self, proxies=None, delay=0, headers=None):
        self.client = httpx.Client(proxies=proxies, follow_redirects=True)
        self.delay = delay
        self.headers = headers if headers else {}
        self.user_agents = load_user_agents()
        self.session_cookies = self.client.cookies
        self.total_bytes_sent = 0
        self.total_bytes_received = 0

    # setting custom headers
    def set_headers(self, custom_headers):
        self.headers.update(custom_headers)

    # rate limiting detection
    def detect_rate_limit(self, response):
        if 'Retry-After' in response.headers:
            delay = int(response.headers['Retry-After'])
            logging.info(f"Rate limiting detected, pausing for {delay} seconds.")
            time.sleep(delay)

    # putting in basic WAF detection
    def detect_waf(self, response):
        waf_headers = ['X-WAF-Detected', 'X-Firewall', 'X-WAF-Protection']
        for header in waf_headers:
            if header in response.headers:
                logging.info(f"WAF detected on {response.url} with header {header}")

    def request(self, method, url, **kwargs):
        headers = self.headers.copy()
        headers['User-Agent'] = choice(self.user_agents)
        kwargs['headers'] = headers
        kwargs['cookies'] = self.session_cookies

        # try loop has exceptions for non-200 responses, WAF detection and rate limiting detection
        try:
            response = self.client.request(method, url, **kwargs)
            response.raise_for_status()
            self.detect_rate_limit(response)
            self.detect_waf(response)
        except httpx.HTTPStatusError as exc:
            logging.error(f"Error response {exc.response.status_code} while requesting {url}: {exc}")
            return None
        except httpx.RequestError as exc:
            logging.error(f"An error occurred while requesting {url}: {exc}")
            return None

        self.total_bytes_sent += len(response.request.content) if response.request.content else 0
        self.total_bytes_received += len(response.content)
        time.sleep(self.delay)
        return response
