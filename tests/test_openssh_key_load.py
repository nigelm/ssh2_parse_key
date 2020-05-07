#!/usr/bin/env python
"""Tests for `ssh2_parse_key` package - loading openssh keys."""
import pytest

from ssh2_parse_key import Ssh2Key

openssh_pubkey_tests = [
    ("dsa", "ssh-dss", "Test ssh key in dsa format"),
    ("ecdsa", "ecdsa-sha2-nistp256", "Test ssh key in ecdsa format"),
    ("ed25519", "ssh-ed25519", "Test ssh key in ed25519 format"),
    ("rsa", "ssh-rsa", "Test ssh key in rsa format"),
]


@pytest.mark.parametrize("format,encryption,comment", openssh_pubkey_tests)
def test_openssh_public_key_load(shared_datadir, format, encryption, comment):
    filename = f"test_key_{format}.pub"
    contents = (shared_datadir / filename).read_text()
    pubkey = Ssh2Key.parse(contents)
    assert pubkey.encryption == encryption
    assert pubkey.type == "public"
    assert pubkey.comment() == comment
    assert len(pubkey.key) > 65


@pytest.mark.parametrize("format,encryption,comment", openssh_pubkey_tests)
def test_openssh_public_key_file(shared_datadir, format, encryption, comment):
    filename = f"test_key_{format}.pub"
    pubkey = Ssh2Key.parse_file(shared_datadir / filename)
    assert pubkey.encryption == encryption
    assert pubkey.type == "public"
    assert pubkey.comment() == comment
    assert len(pubkey.key) > 65


@pytest.mark.parametrize("format,encryption,comment", openssh_pubkey_tests)
def test_openssh_public_key_compare_load_file(
    shared_datadir, format, encryption, comment,
):
    filename = f"test_key_{format}.pub"
    contents = (shared_datadir / filename).read_text()
    pubkey = Ssh2Key.parse(contents)
    fpubkey = Ssh2Key.parse_file(shared_datadir / filename)
    assert pubkey.to_dict() == fpubkey.to_dict()


# end
