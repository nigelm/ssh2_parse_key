"""Tests for `ssh2_parse_key` package - loading openssh keys."""
from pathlib import Path

import pytest

from ssh2_parse_key import Ssh2Key

openssh_pubkey_tests = [
    ("dsa", "ssh-dss", "Test ssh key in dsa format"),
    ("ecdsa", "ecdsa-sha2-nistp256", "Test ssh key in ecdsa format"),
    ("ed25519", "ssh-ed25519", "Test ssh key in ed25519 format"),
    ("rsa", "ssh-rsa", "Test ssh key in rsa format"),
]


@pytest.mark.parametrize(("data_format", "encryption", "comment"), openssh_pubkey_tests)
def test_openssh_public_key_load(shared_datadir: Path, data_format: str, encryption: str, comment: str) -> None:
    """Test openssh public key loading."""
    filename = f"test_key_{data_format}.pub"
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
    assert contents == pubkey.openssh()


@pytest.mark.parametrize(("data_format", "encryption", "comment"), openssh_pubkey_tests)
def test_openssh_public_key_file(shared_datadir: Path, data_format: str, encryption: str, comment: str) -> None:
    """Test openssh public key parsing."""
    filename = f"test_key_{data_format}.pub"
    pubkeys = Ssh2Key.parse_file(shared_datadir / filename)
    pubkey = pubkeys[0]
    assert len(pubkeys) == 1
    assert pubkey.encryption == encryption
    assert pubkey.key_type == "public"
    assert pubkey.comment() == comment
    assert len(pubkey.key) > 65  # noqa: PLR2004


@pytest.mark.parametrize(("data_format", "encryption", "comment"), openssh_pubkey_tests)
def test_openssh_public_key_compare_load_file(
    shared_datadir: Path,
    data_format: str,
    encryption: str,  # noqa: ARG001
    comment: str,  # noqa: ARG001
) -> None:
    """Test file loading is correct."""
    filename = f"test_key_{data_format}.pub"
    contents = (shared_datadir / filename).read_text()
    pubkey = Ssh2Key.parse(contents)[0]
    fpubkey = Ssh2Key.parse_file(shared_datadir / filename)[0]
    assert pubkey == fpubkey


# end
