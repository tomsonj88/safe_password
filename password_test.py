import pytest
from password import Password, EmptyPasswordError


def test_weak_password():
    password = Password("asqwert")
    assert password.is_min_8_chars() is False
    assert password.is_digit_in_str() is False
    assert password.is_upper_letter() is False
    assert password.is_special_char() is False


def test_empty_password():
    with pytest.raises(EmptyPasswordError) as message:
        Password("")
        assert message == "Empty password"


def test_strong_password():
    password = Password("a43G*r#jDW9_")
    assert password.is_min_8_chars() is True
    assert password.is_digit_in_str() is True
    assert password.is_lower_letter() is True
    assert password.is_upper_letter() is True
    assert password.is_special_char() is True


def test_no_lower_letter():
    password = Password("ABC")
    assert password.is_lower_letter() is False
