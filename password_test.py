import pytest
from password import Password, EmptyPasswordError


def test_empty_password():
    with pytest.raises(EmptyPasswordError) as message:
        Password("")
        assert message == "Empty password"


def test_weak_password():
    password = Password("asqwert")
    assert password.is_min_8_chars() is False       # OK
    assert password.is_digit_in_str() is False      # OK
    assert password.is_upper_letter() is False      # OK
    assert password.is_special_char() is False      # OK


def test_strong_password():
    password = Password("a43G*r#jDW9_")
    assert password.is_min_8_chars() is True
    assert password.is_digit_in_str() is True
    assert password.is_lower_letter() is True       # OK
    assert password.is_upper_letter() is True
    assert password.is_special_char() is True


def test_no_lower_letter():
    password = Password("ABC")
    assert password.is_lower_letter() is False


def test_str2byte_conv():
    pswd = Password("table")
    assert type(pswd.str2byte()) == bytes


pswd = Password("personalization")
personalization_hash = "49AA4709BF1E304C4236855E8FFF9C760B75C058".lower()


def test_hash_making():
    assert pswd.make_hash() == personalization_hash


def test_slice_method():
    short_hash = pswd.make_hash_ready_to_send()
    assert len(short_hash) == 5
    for element in range(5):
        assert short_hash[element] == personalization_hash[element]


# TODO: tests for is_safe()
def test_is_safe_password():
    strong = Password("ar58#HJkdi")
    assert strong.is_safe() is True


def test_is_not_safe_password():
    weak = Password("abc")
    assert weak.is_safe() is False
