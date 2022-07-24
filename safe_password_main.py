"""
Safe password main
PYCAMP
"""
import logging
from api import ApiPwnedPasswords
from password_validator import PasswordValidator
from file import File

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

passwords = []
api = ApiPwnedPasswords()
input_file = File("passwords.txt")
passwords = input_file.read_from_file()
output_file = File("bezpieczne.txt")
output_file.write_to_file("", mode="w")

for pswd in passwords:
    password = PasswordValidator(pswd)
    if password.is_safe():
        output_file.write_to_file(str(password) + "\n", mode="a")
