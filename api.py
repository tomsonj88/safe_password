"""
Class API for communication with https://haveibeenpwned.com/
"""
from requests import get
import logging
from logger import set_logger

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)
requests_logger = set_logger("requests-logger", "log_requests.log")

class ConnectionError(Exception):
    pass


class ApiPwnedPasswords:
    url = "https://api.pwnedpasswords.com/range/"

    def get_pwned_passwords(self, first_5_hash_chars: str):
        with get(self.url + first_5_hash_chars, timeout=5) as content:
            requests_logger.info(self.url + first_5_hash_chars)
            return content.text
        # ToDo: ConnectionError

# ToDo: test for "get" method
