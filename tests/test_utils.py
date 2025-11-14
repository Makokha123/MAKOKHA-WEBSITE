import re
from app import sanitize_input, validate_email, allowed_file

def test_sanitize_input_allows_basic_tags():
    raw = '<script>alert(1)</script><p><strong>ok</strong></p>'
    cleaned = sanitize_input(raw)
    assert '<script>' not in cleaned
    assert '<p>' in cleaned
    assert '<strong>' in cleaned


def test_validate_email():
    assert validate_email('user@example.com')
    assert not validate_email('invalid@')


def test_allowed_file_extensions():
    assert allowed_file('x.pdf')
    assert allowed_file('a.JPG')
    assert not allowed_file('bad.exe')
