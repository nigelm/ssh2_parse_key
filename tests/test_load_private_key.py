"""Tests for `ssh2_parse_key` package - load private keys.

Loads the private keys.  This causes exceptions to be raised.
"""
from pathlib import Path

import pytest

from ssh2_parse_key import Ssh2Key

load_privkey_tests = [
    ("dsa", "ssh-dss"),
    ("ecdsa", "ecdsa-sha2-nistp256"),
    ("ed25519", "ssh-ed25519"),
    ("rsa", "ssh-rsa"),
]


@pytest.mark.parametrize(("data_format", "encryption"), load_privkey_tests)
def test_load_private_key(shared_datadir: Path, data_format: str, encryption: str) -> None:  # noqa: ARG001
    """Test loading a private key."""
    openssh_filename = f"test_key_{data_format}"
    openssh_contents = (shared_datadir / openssh_filename).read_text()
    with pytest.raises(ValueError):  # noqa: PT011
        keys = Ssh2Key.parse(openssh_contents)  # noqa: F841


@pytest.mark.parametrize(("data_format", "encryption"), load_privkey_tests)
def test_load_missing_key_file(shared_datadir: Path, data_format: str, encryption: str) -> None:  # noqa: ARG001
    """Test loading a missing key."""
    openssh_filename = f"test_key_duff_{data_format}"
    with pytest.raises(OSError):  # noqa: PT011
        keys = Ssh2Key.parse_file(shared_datadir / openssh_filename)  # noqa: F841


# end
