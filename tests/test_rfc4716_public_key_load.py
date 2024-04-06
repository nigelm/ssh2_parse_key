"""Tests for `ssh2_parse_key` package - loading RFC4716 keys."""

from pathlib import Path

import pytest

from ssh2_parse_key import Ssh2Key

rfc4716_pubkey_tests = [
    # The comment fields get mangled by the openssh ssh-keygen conversion function
    (
        "dsa",
        "ssh-dss",
        '"1024-bit DSA, converted by someone@keytests.example.org fro"',
    ),
    (
        "ecdsa",
        "ecdsa-sha2-nistp256",
        '"256-bit ECDSA, converted by someone@keytests.example.org fr"',
    ),
    (
        "ed25519",
        "ssh-ed25519",
        '"256-bit ED25519, converted by someone@keytests.example.org "',
    ),
    (
        "rsa",
        "ssh-rsa",
        '"3072-bit RSA, converted by someone@keytests.example.org fro"',
    ),
]


@pytest.mark.parametrize(("data_format", "encryption", "comment"), rfc4716_pubkey_tests)
def test_rfc4716_public_key_load(shared_datadir: Path, data_format: str, encryption: str, comment: str) -> None:
    """Test with rfc4716 public key."""
    filename = f"test_key_{data_format}_rfc4716.pub"
    contents = (shared_datadir / filename).read_text()
    pubkeys = Ssh2Key.parse(contents)
    pubkey = pubkeys[0]
    assert len(pubkeys) == 1
    assert pubkey.encryption == encryption
    assert pubkey.key_type == "public"
    assert pubkey.comment() == comment
    assert len(pubkey.key) > 65  # noqa: PLR2004
    #
    # check the key round trips OK (will break if any additional crap in file)
    assert contents == pubkey.secsh()
    assert contents == pubkey.rfc4716()


@pytest.mark.parametrize(("data_format", "encryption", "comment"), rfc4716_pubkey_tests)
def test_rfc4716_public_key_file(shared_datadir: Path, data_format: str, encryption: str, comment: str) -> None:
    """Test with rfc4716 public key."""
    filename = f"test_key_{data_format}_rfc4716.pub"
    pubkeys = Ssh2Key.parse_file(shared_datadir / filename)
    pubkey = pubkeys[0]
    assert len(pubkeys) == 1
    assert pubkey.encryption == encryption
    assert pubkey.key_type == "public"
    assert pubkey.comment() == comment
    assert len(pubkey.key) > 65  # noqa: PLR2004


@pytest.mark.parametrize(("data_format", "encryption", "comment"), rfc4716_pubkey_tests)
def test_rfc4716_public_key_compare_load_file(
    shared_datadir: Path,
    data_format: str,
    encryption: str,  # noqa: ARG001
    comment: str,  # noqa: ARG001
) -> None:
    """Test with rfc4716 public key."""
    filename = f"test_key_{data_format}_rfc4716.pub"
    contents = (shared_datadir / filename).read_text()
    pubkey = Ssh2Key.parse(contents)[0]
    fpubkey = Ssh2Key.parse_file(shared_datadir / filename)[0]
    assert pubkey == fpubkey


# end
