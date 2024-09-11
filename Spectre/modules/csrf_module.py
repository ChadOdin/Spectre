# csrf_module.py

import logging

class CSRFModule:
        def __init__(self, http_client):
                self.http_client = http_client

        def check_csrf(self, url, payload):
                logging.info(f"Testing CSRF on {url}")
                headers = {
                        'Content-Type': 'application/x-www-form-urlencoded'
                }

                data = {
                        'username': 'test',
                        'password': 'thisissilly'
                }

                response = self.http_client.send_request(url, method='POST', headers=headers, data=payload)

                if response is None:
                        logging.warning(f"CSRF test failed for {url} using payload {payload}")
                        return

                if "success" in response.text.lower():
                        logging.info(f"Potential CSRF vulnerability detected on {url}")
                else:
                        logging.info(f"No CSRF vulnerability detected for {url}")
