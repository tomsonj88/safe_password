"""
class Password
"""

import logging
from hashlib import sha1

logging.basicConfig(level=logging.INFO)


class EmptyPasswordError(Exception):
    pass


class Password:
    def __init__(self, text):
        if len(text) == 0:
            raise EmptyPasswordError("Empty password")
        self.text = text

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

    def is_safe(self):
        validator = list()
        validator.append(self.is_min_8_chars())
        validator.append(self.is_digit_in_str())
        validator.append(self.is_lower_letter())
        validator.append(self.is_upper_letter())
        validator.append(self.is_special_char())
        # ToDo: feedback from haveibeenpwnd.com
        if all(validator):
#            print(f"Password {self.text} is safe")
            logging.info(f"Password {self.text} is safe")
        else:
#            print(f"Password {self.text} is NOT safe")
            logging.info(f"Password {self.text} is NOT safe")
            print("dupa")

    def make_hash(self):
        password_in_bytes = self.text.encode("utf-8")
        print(password_in_bytes)
        hash = sha1(password_in_bytes).hexdigest()
        print(hash)
        return hash

    def slice_first_5chars_hash(self):
        hash_beginning = self.make_hash()[:5]
        print(hash_beginning)
        return hash_beginning

pswd = Password("qwerty")
# print(pswd.is_min_length())
# print(pswd.is_digit_in_str())
# print(pswd.is_lower_letter())
# print(pswd.is_upper_letter())
# print(pswd.slice_5_first_chars())
# print(pswd.is_special_char())

pswd.make_hash()
pswd.slice_first_5chars_hash()
