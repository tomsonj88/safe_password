"""
Safe password main
PYCAMP
"""
import logging
from password_validator import PasswordValidator, ValidationError
from logger import set_logger

pswd_logger = set_logger("password_logger", "bezpieczne.txt")

passwords = []

with open("passwords.txt") as input_file, open("bezpieczne.txt", mode="w") as output_file:
    for pswd in input_file:
        password = PasswordValidator(pswd)
        try:
            if password.validate():
                logging.info(f"Password {password} is safe")
                output_file.write(str(password))
        except ValidationError as error:
            print(error)
            logging.info(f"Password {password} is NOT safe")
