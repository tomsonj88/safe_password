"""
Class API for communication with https://haveibeenpwned.com/
"""
from requests import get


class ConnectionError(Exception):
    pass


class ApiPwnedPasswords:
    url = "https://api.pwnedpasswords.com/range/"

    def get(self, password: str):
        with get(self.url + password, timeout=5) as content:
            # print(content)
            # print(content.text)
            return content.text


        # ToDo: ConnectionError
