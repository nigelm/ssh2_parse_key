#!/usr/bin/env python
"""
Tests for `ssh2_parse_key` package - can we handle cr/lf.

This modifies the loaded file content to have \r\n line ends
rather than the normal \n line ends.  We want to see if this
breaks things...  It shouldn't!
"""
import pytest

from ssh2_parse_key import Ssh2Key

convert_pubkey_tests = [
    ("dsa", "ssh-dss"),
    ("ecdsa", "ecdsa-sha2-nistp256"),
    ("ed25519", "ssh-ed25519"),
    ("rsa", "ssh-rsa"),
]


@pytest.mark.parametrize("format,encryption", convert_pubkey_tests)
def test_convert_openssh_to_rfc4716(shared_datadir, format, encryption):
    openssh_filename = f"test_key_{format}.pub"
    openssh_contents = (shared_datadir / openssh_filename).read_text()
    openssh_pubkey = Ssh2Key.parse(openssh_contents.replace("\n", "\r\n"))[0]
    rfc4716_filename = f"test_key_{format}_rfc4716.pub"
    rfc4716_contents = (shared_datadir / rfc4716_filename).read_text()
    rfc4716_pubkey = Ssh2Key.parse(rfc4716_contents.replace("\n", "\r\n"))[0]
    # force the comments to be the same
    rfc4716_pubkey.headers["Comment"] = openssh_pubkey.comment()
    #
    # check the generated openssh version matches the loaded one
    assert rfc4716_pubkey.openssh() == openssh_contents


@pytest.mark.parametrize("format,encryption", convert_pubkey_tests)
def test_convert_rfc4716_to_openssh(shared_datadir, format, encryption):
    openssh_filename = f"test_key_{format}.pub"
    openssh_contents = (shared_datadir / openssh_filename).read_text()
    openssh_pubkey = Ssh2Key.parse(openssh_contents.replace("\n", "\r\n"))[0]
    rfc4716_filename = f"test_key_{format}_rfc4716.pub"
    rfc4716_contents = (shared_datadir / rfc4716_filename).read_text()
    rfc4716_pubkey = Ssh2Key.parse(rfc4716_contents.replace("\n", "\r\n"))[0]
    # force the comments to be the same
    openssh_pubkey.headers["Comment"] = rfc4716_pubkey.comment()
    #
    # check the generated openssh version matches the loaded one
    assert openssh_pubkey.secsh() == rfc4716_contents


# end
