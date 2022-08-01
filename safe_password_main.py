"""
Safe password main
PYCAMP
"""
import logging
from api import ApiPwnedPasswords
from password_validator import PasswordValidator
from file import File
from logger import set_logger

pswd_logger = set_logger("password_logger", "bezpieczne.txt")

passwords = []
api = ApiPwnedPasswords()
input_file = File("passwords.txt")
passwords = input_file.read_from_file()
output_file = File("bezpieczne.txt")
output_file.write_to_file("", mode="w")

for pswd in passwords:
    password = PasswordValidator(pswd)
    if password.validate():
        # output_file.write_to_file(str(password) + "\n", mode="a")
        pswd_logger.info(password)
