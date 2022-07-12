"""
class Password
"""

import logging
import time
from hashlib import sha1
from api import ApiPwnedPasswords

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)


class EmptyPasswordError(Exception):
    pass


class Password:
    def __init__(self, text):
        if len(text) == 0:
            raise EmptyPasswordError("Empty password")
        self.text = text

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

    def is_safe(self, hashes: str):
        validator = list()
        validator.append(self.is_min_8_chars())
        validator.append(self.is_digit_in_str())
        validator.append(self.is_lower_letter())
        validator.append(self.is_upper_letter())
        validator.append(self.is_special_char())
        # ToDo: feedback from https://haveibeenpwned.com/
        validator.append(self.is_not_leaked(hashes))
        if all(validator):
            # print(f"Password {self.text} is safe")
            # time.sleep(0.1)
            logging.info(f"Password {self.text} is safe")
            return True
        else:
            # print(f"Password {self.text} is NOT safe")
            # time.sleep(0.1)
            logging.info(f"Password {self.text} is NOT safe")
            return False

    def str2byte(self):
        return self.text.encode("utf-8")

    def make_hash(self):
        password_in_bytes = self.str2byte()
        hash = sha1(password_in_bytes).hexdigest()
        # print(hash)
        return hash

    def slice_5_chars_from_hash(self):
        hash_beginning = self.make_hash()[:5]
        return hash_beginning

    def is_not_leaked(self, hashes: str):
        pswd_hash = self.make_hash().upper()
        pswd_hash = pswd_hash[5:]
        if pswd_hash in hashes:
            return False
        return True


pswd = Password("qwerty")
# print(pswd.is_min_length())
# print(pswd.is_digit_in_str())
# print(pswd.is_lower_letter())
# print(pswd.is_upper_letter())
# print(pswd.slice_5_first_chars())
# print(pswd.is_special_char())

# pswd.make_hash()
# pswd.slice_5_chars()
# pswd.is_safe()
