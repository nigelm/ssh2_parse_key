#!/usr/bin/env python
"""Tests for `ssh2_parse_key` package - load private keys."""
import pytest

from ssh2_parse_key import Ssh2Key

load_privkey_tests = [
    ("dsa", "ssh-dss"),
    ("ecdsa", "ecdsa-sha2-nistp256"),
    ("ed25519", "ssh-ed25519"),
    ("rsa", "ssh-rsa"),
]


@pytest.mark.parametrize("format,encryption", load_privkey_tests)
def test_load_private_key(shared_datadir, format, encryption):
    openssh_filename = f"test_key_{format}"
    openssh_contents = (shared_datadir / openssh_filename).read_text()
    with pytest.raises(ValueError):
        keys = Ssh2Key.parse(openssh_contents)  # noqa: F841


@pytest.mark.parametrize("format,encryption", load_privkey_tests)
def test_load_missing_key_file(shared_datadir, format, encryption):
    openssh_filename = f"test_key_duff_{format}"
    with pytest.raises(OSError):
        keys = Ssh2Key.parse_file(shared_datadir / openssh_filename)  # noqa: F841


# end
