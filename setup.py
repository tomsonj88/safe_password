from setuptools import setup

setup(
    name="password_validator",
    version="0.1",
    description="Package for checking if password is safe",
    packages=["password_validator"],
    install_requires=["requests", "pytest"]
)