"""
Safe password main
PYCAMP
"""
import logging
from api import ApiPwnedPasswords
from password import Password
from file import File

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

passwords = []
api = ApiPwnedPasswords()
input_file = File("passwords.txt")
passwords = input_file.read_from_file()
output_file = File("bezpieczne.txt")
output_file.write_to_file("", mode="w")

for pswd in passwords:
    password = Password(pswd)
    hash_to_send = password.make_hash_ready_to_send()
    hashes = api.get(hash_to_send)
    if password.is_safe(hashes):
        output_file.write_to_file(str(password) + "\n", mode="a")
