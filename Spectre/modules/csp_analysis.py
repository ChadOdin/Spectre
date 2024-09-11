# csp_analysis.py

import logging

class CSPAnalyzer:
        def __init__(self, http_client):
                self.http_client = http_client

        def analyze_csp(self, url):
                csp_header = response.headers.get('Content-Security-Policy')
                if csp_header:
                        logging.info(f"potential vector for CSP bypass: {csp_header}")
                        if "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
                                logging.warning(f"Unsafe CSP directive found on {response.url}")
                        if not any(keyword in csp_header for keyword in ['nonce', 'sha256']):
                                logging.warning(f"CSP with no nonce or hash directive found on {response.url}")


                logging.info(f"CSP headers found for {url}!\n{csp_header}")
                self.parse_csp(csp_header)

        def parse_csp(self, csp_header):
                directives = csp_header.split(';')

                for directive in directives:
                        directive = directive.strip()
                        logging.info(f"Analyzing CSP directive: {directive}")

                        if 'unsafe-inline' in directive or 'unsafe-eval' in directive:
                                logging.warning(f"Potential bypass vector found: {directive}")
                        elif '*' in directive:
                                logging.warning(f"Wildcare directive found! Potential XSS risk: {directive}")
                        else:
                                logging.info(f"Directive seems secure? {directive}")

        def attempt_csp_bypass(self, url, payload):
                logging.info(f"attmpting CSP bypass with payload: {payload}")
                params = {'q': payload}
                response = self.http_client.request('GET', url, params=params)

                if 'script-src' not in response.headers.get('Content-Security-Policy', ''):
                        logging.warning(f"Possible CSP bypass with {payload} on {url}")
                else:
                        logging.info(f"CSP appears to be enforced on {url}!")
