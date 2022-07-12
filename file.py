"""
class file
"""


class File:
    def __init__(self, filename):
        self.filename = filename

    def read_from_file(self, mode="r"):
        with open(self.filename, mode, encoding="utf8") as file:
            return file.read().split("\n")

    def write_to_file(self, data, mode="a"):
        with open(self.filename, mode, encoding="utf8") as file:
            file.write(str(data))





# with open("passwords.txt", encoding="utf8") as file:
#     passwords = file.read().split("\n")