# sqli_module.py

import logging

class SQLIModule:
        def __init__(self, http_client):
                self.http_client = http_client

        def check_sqli(self, url, payload):
                logging.info(f"Testing for SQLi on {url}")
                headers = {
                        'User-Agent': 'SQLi-Tester'
                }

                # injecting payload into url
                sqli_url = f"{url}?id={payload}"
                response = self.http_client.send_request(sqli_url, method='GET', headers=headers)

                if response is None:
                        logging.warning(f"SQLi test failed for {url}. No response received.")
                        return

                if "sql" in resposne.text.lower() or "syntax error" in response.text.lower():
                        logging.info(f"Potential SQLi vulnerability detected for {url}")
                else:
                        logging.info(f"No SQLi vulnerability detected for {url}")
