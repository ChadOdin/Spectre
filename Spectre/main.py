import logging
import argparse
import payload_utils
from csrf_module import CSRFModule
from sqli_module import SQLIModule
from http_client import HttpClient
from xss_module import XSSModule
from csp_analysis import CSPAnalyzer

def log_payload(url, vuln_type, payload, result):
        with open('scan_results.log', 'a') as log_file:
                log_file.write(f"[{vuln_type}] {url} - Payload {payload}, Result: {result}\n")

def test_vulnerabilities(url, client, xss_module, csp_analyzer, csrf_module, sqli_module, payload_type, fuzz):
        logging.info(f"Running ALL vulnerabilities against {url}")

        # xss
        xss_payload = payload_utils.get_payload('xss', payload_type, fuzz=fuzz)
        mutated_xss_payload = payload_utils.mutate_payload(xss_payload)
        xss_module.check_xss(url, xss_payload)

        # csp
        response = client.request("GET", url)
        if response:
                csp_analyzer.analyze_csp(url)

        # SQLi
        sqli_payload = payload_utils.get_payload('sqli', payload_type, fuzz=fuzz)
        if sqli_payload:
                sqli_module.check_sqli(url, sqli_payload)

        # csrf
        csrf_payload =payload_utils.get_payload('csrf', payload_type, fuzz=fuzz)
        if csrf_payload:
                csrf_module.check_csrf(url, csrf_payload)

        # traffic
        sent, received = client.get_traffic_stats()
        logging.info(f"Total bytes sent: {sent}")
        logging.info(f"Total bytes received: {received}")

def main():

        # adding argument parsing here
        parser = argparse.ArguementParser(description="Vuln scanner")
        parser = argparse.ArgumentParser(description="Vuln scanner")
        parser.add_argument("--urls", nargs='+', help="List of URLs to scan from a .txt", required=False)
        parser.add_argument("--vuln", choices=['xss', 'csrf', 'sqli', 'csp', 'all'], help="Type of vulnerability to scan for", required=True)
        parser.add_argument("--proxy", default='http://127.0.0.1:8080', help="Proxy for routing traffic if manual investigation is needed on a successful hit")
        parser.add_argument("--log-level", choices=["debug", "info", "warning"], default='info', help="Set logging level")
        parser.add_argument("--payload-type", choices=['basic', 'advanced', 'polyglot'], default='basic', help="Type of payload to send")
        parser.add_argument("--delay", type=int, default=5, help="self rate limiting to avoid sending too much traffic")
        parser.add_argument("--interactive", action="store_true", help="Enable interactive session")

        args = parser.parse_args()

        logging.basicConfig(level=getattr(logging, args.log_level.upper()), format='%(asctime)s - %(levelname)s - %(message)s')


        # initializing HTTP client (Httpx)
        proxies = {
                'http://': args.proxy,
                'https://': args.proxy
                }

        client = HttpClient(proxies=proxies, delay=5)

        # initializing modules
        xss_module = XSSModule(client)
        csp_analyzer = CSPAnalyzer(client)
        csrf_module = CSRFModule(client)
        sqli_module = SQLIModule(client)

        urls_to_test = args.urls
        for url in urls_to_test:
                logging.info(f"Testing {url} for {args.vuln.upper()}")
                if args.vuln == 'all':
                        test_vulnerabilities(url, client, xss_module, csp_analyzer, args.payload_type)

                elif args.vuln == 'csp':
                        csp_analyzer.analyze_csp(url)
                        if args.interactive:
                                user_confirm = input(f"Do you want to mark {url} as vulnerable?   (Y/N)")
                                if user_confirm.lower() == 'y':
                                        log_payload(url, args.vuln, payload, 'Confirmed by user')
                elif args.vuln == 'xss':
                        xss_payload = payload_utils.get_payload('xss', args.payload_type)
                        xss_module.check_xss(url, payload)
                        logging.info(f"Testing for XSS on {url} with payload: {payload}")
                        if args.interactive:
                                user_confirm = input(f"Do you want to mark {url} as vulnerable?   (Y/N)")
                                if user_confirm.lower() == 'y':
                                        log_payload(url, args.vuln, payload, 'Confirmed by user')

                elif args.vuln == 'csrf':
                        csrf_payload = payload_utils.get_payload('csrf', args.payload_type)
                        csrf_module.check_csrf(url, csrf_payload)
                        logging.info(f"Testing for CSRF on {url} with payload: {payload}")
                        if args.interactive:
                                user_confirm = input(f"Do you want to mark {url} as vulnerable?   (Y/N)")
                                if user_confirm.lower() == 'y':
                                        log_payload(url, args.vuln, payload, 'Confirmed by user')

                elif args.vuln == 'sqli':
                        sqli_payload = payload_utils.get_payload('sqli', args.payload_type)
                        sqli_module.check_sqli(url, sqli_payload)
                        logging.info(f"Testing for SQLi on {url} with payload {payload}")
                        if args.interactive:
                                user_confirm = input(f"Do you want to mark {url} as vulnerable?   (Y/N)")
                                if user_confirm.lower() == 'y':
                                        log_payload(url, args.vuln, payload, 'Confirmed by user')



                sent, received = client.get_traffic_stats()
                logging.info(f"Total bytes sent: {sent}")
                logging.info(f"Total bytes received: {received}")
        client.close()
if __name__ == "__main__":
        main()
