"""
Safe password main
PYCAMP
"""
import logging
from api import ApiPwnedPasswords
from password_validator import PasswordValidator
from logger import set_logger

pswd_logger = set_logger("password_logger", "bezpieczne.txt")

passwords = []
api = ApiPwnedPasswords()

with open("passwords.txt") as input_file, open("bezpieczne.txt", mode="w") as output_file:
    for pswd in input_file:
        password = PasswordValidator(pswd)
        if password.validate():
            output_file.write(str(password))
            # pswd_logger.info(password)
