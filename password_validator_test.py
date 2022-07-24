import pytest
from password_validator import PasswordValidator, EmptyPasswordError
from api import ApiPwnedPasswords


def test_empty_password():
    with pytest.raises(EmptyPasswordError) as message:
        PasswordValidator("")
        assert message == "Empty password"


def test_weak_password():
    password = PasswordValidator("asqwert")
    assert password.is_min_8_chars() is False       # OK
    assert password.is_digit_in_str() is False      # OK
    assert password.is_upper_letter() is False      # OK
    assert password.is_special_char() is False      # OK


def test_strong_password():
    password = PasswordValidator("a43G*r#jDW9_")
    assert password.is_min_8_chars() is True
    assert password.is_digit_in_str() is True
    assert password.is_lower_letter() is True       # OK
    assert password.is_upper_letter() is True
    assert password.is_special_char() is True


def test_no_lower_letter():
    password = PasswordValidator("ABC")
    assert password.is_lower_letter() is False


def test_str2byte_conv():
    pswd = PasswordValidator("table")
    assert type(pswd.str2byte()) == bytes


pswd = PasswordValidator("personalization")
personalization_hash = "49AA4709BF1E304C4236855E8FFF9C760B75C058".lower()


def test_hash_making():
    assert pswd.make_hash() == personalization_hash


def test_slice_method():
    short_hash = pswd.make_hash_ready_to_send()
    assert len(short_hash) == 5
    for element in range(5):
        assert short_hash[element] == personalization_hash[element]


password = PasswordValidator("test")
password2 = PasswordValidator("python")
resp_api = """FD8D510BFF2210462F26307C2143E990E6E:3
            FDFAEE848356AD27F8FB494E5C1B11956C2:3
            FDFD0D9BC12735B077ACF1FA63D6F42229D:1
            FE5CCB19BA61C4C0873D391E987982FBBD3:86453
            FE872CEF798B9CAD912B101B1FCA6E054C6:1
            FF36DC7D3284A39991ADA90CAF20D1E3C0D:1
            FFC7FE7DB601419CF0E1094361291D846C5:1
            FFF983A91443AE72BD98E59ADAB93B31974:2"""


def test_check_password_leakage(requests_mock):
    assert password.check_password_leakage() is True
    assert password2.check_password_leakage() is False


# tests for test_is_safe_password & test_is_not_safe_password
strong = PasswordValidator("ar58#HJkdi")
api = ApiPwnedPasswords()
strong_response = """958791E442C6EBD810568CC9D7FA852D797:15
95DC899DEECC0C29B8789CA143C65F577E9:1
95F9A1CF60699D487EE90EF3DDDCABF4309:4
9634FDC1594783EAF03B18675D522B1782B:3
9777332A7090B57C383DA53A5494A7253BF:16"""
print(strong_response)
weak = password


def test_is_safe_password():
    assert strong.is_safe(strong_response) is True


def test_is_not_safe_password():
    assert weak.is_safe(resp_api) is False
