"""
Class API for communication with https://haveibeenpwned.com/
"""
from requests import get


class ConnectionError(Exception):
    pass


class ApiPwnedPasswords:
    url = "https://api.pwnedpasswords.com/range/"

    def get(self, first_5_hash_chars: str):
        with get(self.url + first_5_hash_chars, timeout=5) as content:
            return content.text
        # ToDo: ConnectionError
