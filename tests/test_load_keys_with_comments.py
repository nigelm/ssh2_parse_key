"""Tests for `ssh2_parse_key` package - load keys with comments.

Uses a test from the multiple keys tests but puts # comment
lines in between the keys to see if that breaks things.
"""
from pathlib import Path

import pytest  # noqa: F401

from ssh2_parse_key import Ssh2Key

multiple_key_tests = [
    "dsa",
    "ecdsa",
    "ed25519",
    "rsa",
]


def test_load_multiple_mixed_pubkey_key(shared_datadir: Path) -> None:
    """Test a mix of public keys."""
    key_contents = []
    for data_format in multiple_key_tests:
        openssh_filename = f"test_key_{data_format}.pub"
        openssh_contents = (shared_datadir / openssh_filename).read_text()
        key_contents.append(openssh_contents)
        rfc4716_filename = f"test_key_{data_format}.pub"
        rfc4716_contents = (shared_datadir / rfc4716_filename).read_text()
        key_contents.append(rfc4716_contents)
    all_keys = "\n# comment\n".join(key_contents)
    # print(all_keys)
    keys = Ssh2Key.parse(all_keys)
    assert len(keys) == len(multiple_key_tests) * 2
    for key in keys:
        assert isinstance(key, Ssh2Key)


# end
