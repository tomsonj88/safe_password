"""
class Password
"""

import logging
from hashlib import sha1
from abc import ABC, abstractmethod
from logger import set_logger
from requests import get

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', level=logging.INFO)


class ValidatorInterface(ABC):
    @abstractmethod
    def validate(self):
        pass


class EmptyPasswordError(Exception):
    pass


class ValidationError(Exception):
    pass


class PasswordValidator(ValidatorInterface):
    def __init__(self, password):
        if len(password) == 0:
            logging.error("Password can't be empty.")
            raise EmptyPasswordError("Empty password")
        self.password = password

    def __str__(self):
        return self.password

    def is_min_length(self, min_length=8) -> bool:
        if len(self.password) >= min_length:
            return True
        raise ValidationError(f"Text doesn't contain {min_length} chars")

    def is_digit_in_str(self) -> bool:
        result = [char.isdigit() for char in self.password]
        if any(result):
            return True
        raise ValidationError("Text doesn't contain any digit")

    def is_lower_letter(self) -> bool:
        result = [char.islower() for char in self.password]
        if any(result):
            return True
        raise ValidationError("Text doesn't contain lower letter")

    def is_upper_letter(self) -> bool:
        result = [char.isupper() for char in self.password]
        if any(result):
            return True
        raise ValidationError("Text doesn't contain upper letter")

    def is_special_char(self) -> bool:
        for char in self.password:
            if not char.isalnum():
                return True
        raise ValidationError("Text doesn't contain special character")

    def validate(self):
        validator = [
            self.is_min_length(),
            self.is_digit_in_str(),
            self.is_lower_letter(),
            self.is_upper_letter(),
            self.is_special_char(),
            not self.check_password_leakage()
            ]
        if all(validator):
            return True
        return False

    def str2byte(self):
        return self.password.encode("utf-8")

    def make_hash(self):
        password_in_bytes = self.str2byte()
        password_hash = sha1(password_in_bytes).hexdigest()
        return password_hash

    def check_password_leakage(self):
        hash_password_beggining = self.make_hash()[:5]
        url = "https://api.pwnedpasswords.com/range/"
        hash_password_end = self.make_hash()[5:].upper()
        with get(url + hash_password_beggining) as content:
            if hash_password_end in content.text:
                raise ValidationError("This password was leaked")
            return False
