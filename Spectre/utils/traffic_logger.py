# utils/traffic_logger.py

import logging

# initializing logging engine
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TrafficLogger:
    def __init__(self):
        self.total_bytes_sent = 0
        self.total_bytes_received = 0

    def log_traffic(self, bytes_sent, bytes_received):
        self.total_bytes_sent += bytes_sent
        self.total_bytes_received += bytes_received
        logging.info(f"Total bytes sent: {self.total_bytes_sent}")
        logging.info(f"Total bytes received: {self.total_bytes_received}")
