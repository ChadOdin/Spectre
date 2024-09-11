# xss_module.py

from payload_utils import mutate_payload, get_payload
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

class XSSModule:
        def __init__(self, http_client):
                self.http_client = http_client

        def check_xss(self, url, payload_type='basic'):
        # pulling payloads from our payloads.yaml file
                payload = get_payload('xss', payload_type)
                mutated_payloads = mutate_paylaod(payload)

                # doing context aware injection here
                for payload in mutated_payloads:
                        logging.info(f"Testing XSS payload with {payload}")
                        response = self.http_client.request('GET', url, params={'q': payload})
                        if response and payload in response.text:
                                log_payload(url, 'xss', payload, 'reflected')
                        # putting DOM-based XSS detection here
                        if self.check_dom_xss(url):
                                logging.info(f"Potential XSS detected for {url} using {payload}")
                        else:
                                logging.info(f"No XSS vector detected for {url} using {payload}")

        # putting dom-based XSS logic here
        def check_dom_xss(self, url):
                options = Options()
                options.headless = True
                driver = webdriver.Chrome(options=options)
                driver.get(url)
                try:
                        # check here to see if any scripts are executing
                        if '<script>alert' in driver.page_source:
                                driver.quit()
                                return True
                        else:
                                driver.quit()
                                return False
                except Exception as e:
                        logging.error(f"Error checking for DOM-Based XSS: {e}")
                        driver.quit()
                        return False

        def capture_screenshot(self, url):
                options = Options()
                options.headless = True
                driver = webdriver.Chrome(options=options)
                driver.get(url)
                screenshot_name = f"screenshot_{url.replace('http://', '').replace('https://', '').replace('/', '_')}.png"
                driver.save_screenshot(screenshot_name)
                logging.info(f"Screenshot saved: {screenshot_name}")
                driver.quit()
