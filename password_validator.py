"""
class Password
"""

import logging
from hashlib import sha1
from api import ApiPwnedPasswords

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)


class EmptyPasswordError(Exception):
    pass


class PasswordValidator:
    def __init__(self, password):
        if len(password) == 0:
            logging.error("Password can't be empty.")
            raise EmptyPasswordError("Empty password")
        self.password = password

    def __str__(self):
        return self.password

    def is_min_8_chars(self) -> bool:
        if len(self.password) >= 8:
            return True
        return False

    def is_digit_in_str(self) -> bool:
        result = [char.isdigit() for char in self.password]
        return any(result)

    def is_lower_letter(self) -> bool:
        result = [char.islower() for char in self.password]
        return any(result)

    def is_upper_letter(self) -> bool:
        result = [char.isupper() for char in self.password]
        return any(result)

    def is_special_char(self) -> bool:
        result = []
        for char in self.password:
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
        # ToDo: feedback from https://haveibeenpwned.com/
        validator.append(not self.check_password_leakage())
        if all(validator):
            # print(f"Password {self.password} is safe")
            logging.info(f"Password {self.password} is safe")
            return True
        else:
            # print(f"Password {self.password} is NOT safe")
            logging.info(f"Password {self.password} is NOT safe")
            return False

    def str2byte(self):
        return self.password.encode("utf-8")

    def make_hash(self):
        password_in_bytes = self.str2byte()
        hash = sha1(password_in_bytes).hexdigest()
        return hash

    def make_hash_ready_to_send(self):
        hash_beginning = self.make_hash()[:5]
        return hash_beginning

    def check_password_leakage(self):
        hash_password = self.make_hash_ready_to_send()
        api = ApiPwnedPasswords()
        api_response = api.get_pwned_passwords(hash_password)
        pswd_hash = self.make_hash()[5:].upper()
        if pswd_hash in api_response:
            return True
        return False
