"""
Password Validator module
"""
from abc import ABC, abstractmethod
from hashlib import sha1
import logging
from requests import get
from logger import set_logger




logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s', level=logging.INFO)
request_logger = set_logger("request", "log_requests.log", logging.INFO, mode="w")


class ValidatorInterface(ABC):
    """
    Interface for validator
    """
    # pylint: disable=too-few-public-methods)
    @abstractmethod
    def validate(self):
        """Force to implement validate method"""


class EmptyPasswordError(Exception):
    """Exception for empty password"""


class ValidationError(Exception):
    """Exception for validation error"""


class PasswordValidator(ValidatorInterface):
    """Class for password validation"""
    def __init__(self, password):
        if len(password) == 0:
            logging.error("Password can't be empty.")
            raise EmptyPasswordError("Empty password")
        self.password = password

    def __str__(self):
        return self.password

    def is_min_length(self, min_length: int = 8) -> bool:
        """
        Method checking if password has minimum number of chars.
        :param min_length: minimal number of chars
        :return: bool
        """
        if len(self.password) >= min_length:
            return True
        raise ValidationError(f"Text doesn't contain {min_length} chars")

    def is_digit_in_str(self) -> bool:
        """
        Method checking if password has digit
        :return: bool
        """
        result = [char.isdigit() for char in self.password]
        if any(result):
            return True
        raise ValidationError("Text doesn't contain any digit")

    def is_lower_letter(self) -> bool:
        """
        Method checking if password has lower letter.
        :return: bool
        """
        result = [char.islower() for char in self.password]
        if any(result):
            return True
        raise ValidationError("Text doesn't contain lower letter")

    def is_upper_letter(self) -> bool:
        """
        Method checking if password has upper letter
        :return: bool
        """
        result = [char.isupper() for char in self.password]
        if any(result):
            return True
        raise ValidationError("Text doesn't contain upper letter")

    def is_special_char(self) -> bool:
        """
        Method checking if password has special character.
        :return: bool
        """
        for char in self.password:
            if not char.isalnum():
                return True
        raise ValidationError("Text doesn't contain special character")

    def validate(self) -> bool:
        """
        Method checking if password is a safe password.
        :return: bool
        """
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

    def str2byte(self) -> bytes:
        """Method to convert string to bytes using coding utf-8"""
        return self.password.encode("utf-8")

    def make_hash(self) -> str:
        """
        Method make conversion to hash using SHA-1 algorithm
        :return:
        """
        password_in_bytes = self.str2byte()
        password_hash = sha1(password_in_bytes).hexdigest()
        return password_hash

    def check_password_leakage(self):
        """
        Method checking if password is a leaked.
        :return: bool
        """
        hash_password_beggining = self.make_hash()[:5]
        url = "https://api.pwnedpasswords.com/range/"
        full_url = url + hash_password_beggining
        hash_password_end = self.make_hash()[5:].upper()
        with get(full_url) as content:
            request_logger.info(full_url)
            if hash_password_end in content.text:
                raise ValidationError("This password was leaked")
            return False
