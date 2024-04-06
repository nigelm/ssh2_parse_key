r"""Tests for `ssh2_parse_key` package - can we handle cr/lf.

This modifies the loaded file content to have \r\n line ends
rather than the normal \n line ends.  We want to see if this
breaks things...  It shouldn't!
"""

from pathlib import Path

import pytest

from ssh2_parse_key import Ssh2Key

convert_pubkey_tests = [
    ("dsa", "ssh-dss"),
    ("ecdsa", "ecdsa-sha2-nistp256"),
    ("ed25519", "ssh-ed25519"),
    ("rsa", "ssh-rsa"),
]


@pytest.mark.parametrize(("data_format", "encryption"), convert_pubkey_tests)
def test_convert_openssh_to_rfc4716(shared_datadir: Path, data_format: str, encryption: str) -> None:  # noqa: ARG001
    """Test convert openssh -> rfc4716."""
    openssh_filename = f"test_key_{data_format}.pub"
    openssh_contents = (shared_datadir / openssh_filename).read_text()
    openssh_pubkey = Ssh2Key.parse(openssh_contents.replace("\n", "\r\n"))[0]
    rfc4716_filename = f"test_key_{data_format}_rfc4716.pub"
    rfc4716_contents = (shared_datadir / rfc4716_filename).read_text()
    rfc4716_pubkey = Ssh2Key.parse(rfc4716_contents.replace("\n", "\r\n"))[0]
    # force the comments to be the same
    rfc4716_pubkey.headers["Comment"] = openssh_pubkey.comment()
    #
    # check the generated openssh version matches the loaded one
    assert rfc4716_pubkey.openssh() == openssh_contents


@pytest.mark.parametrize(("data_format", "encryption"), convert_pubkey_tests)
def test_convert_rfc4716_to_openssh(shared_datadir: Path, data_format: str, encryption: str) -> None:  # noqa: ARG001
    """Test convert rfc4716 -> openssh."""
    openssh_filename = f"test_key_{data_format}.pub"
    openssh_contents = (shared_datadir / openssh_filename).read_text()
    openssh_pubkey = Ssh2Key.parse(openssh_contents.replace("\n", "\r\n"))[0]
    rfc4716_filename = f"test_key_{data_format}_rfc4716.pub"
    rfc4716_contents = (shared_datadir / rfc4716_filename).read_text()
    rfc4716_pubkey = Ssh2Key.parse(rfc4716_contents.replace("\n", "\r\n"))[0]
    # force the comments to be the same
    openssh_pubkey.headers["Comment"] = rfc4716_pubkey.comment()
    #
    # check the generated openssh version matches the loaded one
    assert openssh_pubkey.secsh() == rfc4716_contents


def test_load_multiple_rfc4716(shared_datadir: Path) -> None:
    """Test loading multiple test_load_multiple_rfc4716."""
    contents = []
    for data_format, _encryption in convert_pubkey_tests:
        rfc4716_filename = f"test_key_{data_format}_rfc4716.pub"
        rfc4716_contents = (shared_datadir / rfc4716_filename).read_text()
        contents.append(rfc4716_contents.replace("\n", "\r\n"))
    keys = Ssh2Key.parse("".join(contents))
    #
    # check we have the right number
    assert len(keys) == len(contents)


def test_load_inline() -> None:
    """Test loading inline keys."""
    key_contents = (
        "---- BEGIN SSH2 PUBLIC KEY ----\r\n"
        "Comment: nigel@weatherwax.intechnology.co.uk\r\n"
        "AAAAC3NzaC1lZDI1NTE5AAAAIC8LzfyUV6Z7hZu7dPZ6aDpE/dMRjIaIlaFgQB/vf1FH\r\n"
        "---- END SSH2 PUBLIC KEY ----\r\n"
        "---- BEGIN SSH2 PUBLIC KEY ----\r\n"
        "Comment: nigel@weatherwax.intechnology.co.uk\r\n"
        "AAAAC3NzaC1lZDI1NTE5AAAAIC8LzfyUV6Z7hZu7dPZ6aDpE/dMRjIaIlaFgQB/vf1FH\r\n"
        "---- END SSH2 PUBLIC KEY ----\r\n"
        "---- BEGIN SSH2 PUBLIC KEY ----\r\n"
        "Comment: nigel@weatherwax-2016\r\n"
        "AAAAB3NzaC1yc2EAAAADAQABAAABgQDUY4IlGS2XSu+HpopBTE2FFOUzg6zY+B9h0I3kG5\r\n"
        "EmUNdV/ybduOH/zTuynNL4nfF1dPUxFmd+YfwAmmBxYXhLA5vHFdcASK5Lg4GazJVVy+nO\r\n"
        "aw3KedsO4IpRgDDwUTG6mwUp5WNXOrjdQJDhSGucaLvXYOZcxP2juvKgkOQHQp2oEmftC1\r\n"
        "WcYCR0BKx7NlctFHw+3hMI3ZHqRulnMKZ7MCOjDUEBX3XW5LTlTtT8XrUm6aZ+AxLoyhQI\r\n"
        "K7Ny7yj7lyuVD56hvzU6JhAKeW+TZ3+Sewo92/ljVy3fT6KHXP7keUJVkDwPFir8afsWEv\r\n"
        "hVi9fjbWNKic2YUz18f3t5qsb0y9Qw88UIM7argp7ncg0oSrmh+0R92+wLz3VAmR7iD4Wp\r\n"
        "Rk45zKU/bnRjdYw8omJJQ4qQuFFDF83qpbbSncDBtn/hMzqP6Ynbis6HqsYpbLKYByNvYZ\r\n"
        "tMVsP4DAn5zhsBbBUJm7F6nwY4VcTZoUd+KYD3+DOHigaI6vcbxas=\r\n"
        "---- END SSH2 PUBLIC KEY ----\r\n"
        "---- BEGIN SSH2 PUBLIC KEY ----\r\n"
        "Comment: nigel@weatherwax.intechnology.co.uk\r\n"
        "AAAAC3NzaC1lZDI1NTE5AAAAIC8LzfyUV6Z7hZu7dPZ6aDpE/dMRjIaIlaFgQB/vf1FH\r\n"
        "---- END SSH2 PUBLIC KEY ----\r\n"
    )
    keys = Ssh2Key.parse("".join(key_contents))
    assert len(keys) == 4  # noqa: PLR2004


# end
