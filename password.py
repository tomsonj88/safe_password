"""
class Password
"""

import logging
from hashlib import sha1

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)


class EmptyPasswordError(Exception):
    pass


class Password:
    def __init__(self, password):
        if len(password) == 0:
            raise EmptyPasswordError("Empty password")
        self.text = password

    def __str__(self):
        return self.text

    def is_min_8_chars(self) -> bool:
        if len(self.text) >= 8:
            return True
        return False

    def is_digit_in_str(self) -> bool:
        result = [char.isdigit() for char in self.text]
        return any(result)

    def is_lower_letter(self) -> bool:
        result = [char.islower() for char in self.text]
        return any(result)

    def is_upper_letter(self) -> bool:
        result = [char.isupper() for char in self.text]
        return any(result)

    def is_special_char(self) -> bool:
        result = []
        for char in self.text:
            if 33 <= ord(char) <= 47 \
                    or 58 <= ord(char) <= 64 \
                    or 91 <= ord(char) <= 96 \
                    or 123 <= ord(char) <= 126:
                result.append(True)
            else:
                result.append(False)
        return any(result)

    def is_safe(self, api_response: str):
        validator = list()
        validator.append(self.is_min_8_chars())
        validator.append(self.is_digit_in_str())
        validator.append(self.is_lower_letter())
        validator.append(self.is_upper_letter())
        validator.append(self.is_special_char())
        # ToDo: feedback from https://haveibeenpwned.com/
        validator.append(not self.check_password_leakage(api_response))
        if all(validator):
            # print(f"Password {self.text} is safe")
            logging.info(f"Password {self.text} is safe")
            return True
        else:
            # print(f"Password {self.text} is NOT safe")
            logging.info(f"Password {self.text} is NOT safe")
            return False

    def str2byte(self):
        return self.text.encode("utf-8")

    def make_hash(self):
        password_in_bytes = self.str2byte()
        hash = sha1(password_in_bytes).hexdigest()
        return hash

    def make_hash_ready_to_send(self):
        hash_beginning = self.make_hash()[:5]
        return hash_beginning

    def check_password_leakage(self, api_response:str):
        pswd_hash = self.make_hash()[5:].upper()
        if pswd_hash in api_response:
            return True
        return False
