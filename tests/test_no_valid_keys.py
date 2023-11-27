"""Tests for `ssh2_parse_key` package - load keys with comments.

Uses a test from the multiple keys tests but puts # comment
lines in between the keys to see if that breaks things.
"""
import pytest

from ssh2_parse_key import Ssh2Key

invalid_key_tests = [
    "",  # empty
    "\n\n\n\n\n",  # only blank lines
    "\n# comment\n#comment\n\n\n",  # only comment lines
]


def test_load_no_valid_key_key() -> None:
    """Test what happens if keys are invalid."""
    for content in invalid_key_tests:
        with pytest.raises(ValueError):  # noqa: PT011
            keys = Ssh2Key.parse(content)  # noqa: F841


# end
