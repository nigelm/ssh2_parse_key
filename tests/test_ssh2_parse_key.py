#!/usr/bin/env python
"""Tests for `ssh2_parse_key` package."""
import pytest  # noqa: F401

from ssh2_parse_key import Ssh2Key


def load_ecdsa_pubkey():
    return Ssh2Key.parse(
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMK1IxOZEKvh96sRuyuK9/Cf3iRLTQeXBx6JcURpoZOeFjgHQwNXccxWAwzheIEpqSAEYKTYs2BW0M/Kc1FC7ps= ecdsa-sha2-nistp256 key",  # noqa: E501
    )[0]


def test_load_ecdsa_pubkey():
    pubkey = load_ecdsa_pubkey()
    assert (
        pubkey.key
        == "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMK1IxOZEKvh96sRuyuK9/Cf3iRLTQeXBx6JcURpoZOeFjgHQwNXccxWAwzheIEpqSAEYKTYs2BW0M/Kc1FC7ps="  # noqa: E501,W503
    )
    assert pubkey.encryption == "ecdsa-sha2-nistp256"
    assert pubkey.type == "public"
    assert pubkey.comment() == "ecdsa-sha2-nistp256 key"


# end
