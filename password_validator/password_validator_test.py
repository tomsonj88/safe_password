"""
Test for password validator module
"""

import pytest
from password_validator.password_validator import (
    PasswordValidator,
    EmptyPasswordError,
    ValidationError
    )


def test_empty_password():
    """
    Test for exception if password is empty
    """
    with pytest.raises(EmptyPasswordError) as message:
        PasswordValidator("")
    assert "Empty password" in str(message)


def test_weak_password():
    """
    Test for weak password. It checks if exception are raises in case of
    password with no minimal length, no digit, no upper letter
    and no special character.
    """
    password = PasswordValidator("asqwert")
    with pytest.raises(ValidationError) as error:
        password.is_min_length()
    assert "Text doesn't contain 8 chars" in str(error.value)
    with pytest.raises(ValidationError) as error:
        password.is_digit_in_str()
    assert "Text doesn't contain any digit" in str(error.value)
    with pytest.raises(ValidationError) as error:
        password.is_upper_letter()
    assert "Text doesn't contain upper letter" in str(error.value)
    with pytest.raises(ValidationError) as error:
        password.is_special_char()
    assert "Text doesn't contain special character" in str(error.value)


def test_strong_password():
    """
    Test for strong password. It checks if methods for password
    with minimal length, digit, lower and upper letter,
    with special character returns True"
    """
    password = PasswordValidator("a43G*r#jDW9_")

    assert password.is_min_length() is True
    assert password.is_digit_in_str() is True
    assert password.is_lower_letter() is True
    assert password.is_upper_letter() is True
    assert password.is_special_char() is True


def test_no_lower_letter():
    """
    Test checks if exception are raises in case of
    password doesn't contain lower letter.
    """
    password = PasswordValidator("ABC")
    with pytest.raises(ValidationError) as error:
        password.is_lower_letter()
    assert "Text doesn't contain lower letter" in str(error.value)


def test_str2byte_conv():
    """
    Test for str to byte conversion
    """
    password = PasswordValidator("table")
    assert isinstance(password.str2byte(), bytes)


def test_hash_making():
    """
    Test to check if hash using SHA-1 is generated properly.
    """
    pswd = PasswordValidator("personalization")
    personalization_hash = "49AA4709BF1E304C4236855E8FFF9C760B75C058".lower()
    assert pswd.make_hash() == personalization_hash


def test_password_has_been_pwned(requests_mock):
    """
    Test checks if leaked password raises exception
    """
    password = PasswordValidator("test")
    data = """
            FDFAEE848356AD27F8FB494E5C1B11956C2:3
            FDFD0D9BC12735B077ACF1FA63D6F42229D:1
            FE5CCB19BA61C4C0873D391E987982FBBD3:86453
            FE872CEF798B9CAD912B101B1FCA6E054C6:1
            """
    requests_mock.get("https://api.pwnedpasswords.com/range/a94a8", text=data)
    with pytest.raises(ValidationError) as error:
        password.check_password_leakage()
    assert "This password was leaked" in str(error.value)


def test_password_has_not_been_pwned(requests_mock):
    """
    Test checks if password wasn't leak
    """
    password = PasswordValidator("python_is_the_anwser")
    data = """
            FDFAEE848356AD27F8FB494E5C1B11956C2:3
            FDFD0D9BC12735B077ACF1FA63D6F42229D:1
            FE5CCB19BA61C4C0873D391E987982FBBD3:86453
            FE872CEF798B9CAD912B101B1FCA6E054C6:1
            """
    requests_mock.get("https://api.pwnedpasswords.com/range/e470c", text=data)
    assert password.check_password_leakage() is False


def test_is_safe_password(requests_mock):
    """
    Test checks if password validate method return properly, that password is safe
    :param requests_mock:
    :return:
    """
    strong_pswd = PasswordValidator("ar58#HJkdi")
    data = """
            0FD7ED272E8DC9732E9C389AC6503D0C3BC:7
            0FF326BF498DAD6C732F8A006E56E8BBC4A:1
            1026E8593048D8969A471EA86BD35FA588F:2
            106186E54D6664416F354E3F2208A21669C:2
            """
    requests_mock.get("https://api.pwnedpasswords.com/range/21ba5", text=data)
    assert strong_pswd.validate() is True


def test_is_not_safe_password(requests_mock):
    """
    Test checks if password_validate method raise exception that
    password is not safe and show why
    :param requests_mock:
    :return:
    """
    weak_pswd = PasswordValidator("python")
    data = """
            2797D4688208BA70C9DCA74D5A922FCECBD:2
            27AB125768AB71C6F16EDE2EE5C1012C623:2
            27B51436AD86D07C7CF5D69BDA2644984DE:16202
            27C6E2C96325CCB9EDCA04203B68D7D5B95:1
            28379EF3D8C09702DCDBFD8B4F94D3DAB36:1
            2891F3B1CB433A969D5F54692E5D68F4D77:14
            """
    requests_mock.get("https://api.pwnedpasswords.com/range/42352", text=data)
    with pytest.raises(ValidationError) as error:
        weak_pswd.validate()
    assert "Text doesn't contain 8 chars" in str(error.value)
