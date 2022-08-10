"""
Safe password main
PYCAMP
"""
import logging
from password_validator import PasswordValidator, ValidationError
from logger import set_logger

pswd_logger = set_logger("password_logger", "bezpieczne.txt")

with open("passwords.txt") as input_file, open("bezpieczne.txt", mode="w") as output_file:
    for pswd in input_file:
        password = PasswordValidator(pswd)
        try:
            if password.validate():
                logging.info(f"Password {str(pswd).strip()} is safe")
                output_file.write(str(password))
        except ValidationError as error:
            logging.info(f"Password {str(password).strip()} is NOT safe")
            logging.error(f"{str(password).strip()} - {error}")
            #print(error)
