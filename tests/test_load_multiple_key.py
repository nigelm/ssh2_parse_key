#!/usr/bin/env python
"""Tests for `ssh2_parse_key` package - load private keys."""
import pytest  # noqa: F401

from ssh2_parse_key import Ssh2Key

multiple_key_tests = [
    "dsa",
    "ecdsa",
    "ed25519",
    "rsa",
]


def test_load_multiple_openssh_pubkey_key(shared_datadir):
    key_contents = []
    for format in multiple_key_tests:
        openssh_filename = f"test_key_{format}.pub"
        openssh_contents = (shared_datadir / openssh_filename).read_text()
        key_contents.append(openssh_contents)
    all_keys = "\n".join(key_contents)
    print(all_keys)
    keys = Ssh2Key.parse(all_keys)
    assert len(keys) == len(multiple_key_tests)
    for key in keys:
        assert isinstance(key, Ssh2Key)


def test_load_multiple_rfc4716_pubkey_key(shared_datadir):
    key_contents = []
    for format in multiple_key_tests:
        rfc4716_filename = f"test_key_{format}.pub"
        rfc4716_contents = (shared_datadir / rfc4716_filename).read_text()
        key_contents.append(rfc4716_contents)
    all_keys = "\n".join(key_contents)
    print(all_keys)
    keys = Ssh2Key.parse(all_keys)
    assert len(keys) == len(multiple_key_tests)
    for key in keys:
        assert isinstance(key, Ssh2Key)


def test_load_multiple_mixed_pubkey_key(shared_datadir):
    key_contents = []
    for format in multiple_key_tests:
        openssh_filename = f"test_key_{format}.pub"
        openssh_contents = (shared_datadir / openssh_filename).read_text()
        key_contents.append(openssh_contents)
        rfc4716_filename = f"test_key_{format}.pub"
        rfc4716_contents = (shared_datadir / rfc4716_filename).read_text()
        key_contents.append(rfc4716_contents)
    all_keys = "\n".join(key_contents)
    print(all_keys)
    keys = Ssh2Key.parse(all_keys)
    assert len(keys) == len(multiple_key_tests) * 2
    for key in keys:
        assert isinstance(key, Ssh2Key)


# end
