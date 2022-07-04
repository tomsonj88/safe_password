"""
Safe password main
PYCAMP
"""
import logging
from password import Password

logging.basicConfig(level=logging.INFO)

passwords = []
with open("passwords.txt") as file:
    passwords = file.read().split("\n")

for pswd in passwords:
    print(pswd)
    result = Password(pswd)
    result.is_safe()
