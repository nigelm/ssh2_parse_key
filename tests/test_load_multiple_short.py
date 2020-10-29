#!/usr/bin/env python
"""Tests for `ssh2_parse_key` package - loading multiple short keys."""
import pytest  # noqa: F401

from ssh2_parse_key import Ssh2Key


def test_load_inline():
    """This exposed a bug in the parser previously"""
    key_contents = (
        "---- BEGIN SSH2 PUBLIC KEY ----\n"
        "Comment: my-key@example.org\n"
        "AAAAC3NzaC1lZDI1NTE5AAAAIHV8K5j1UNZSmAl4Xq7Yp8Qe1nN74B5NA7UyZDvz0H4M\n"
        "---- END SSH2 PUBLIC KEY ----\n"
        "---- BEGIN SSH2 PUBLIC KEY ----\n"
        "Comment: my-key@example.org\n"
        "AAAAC3NzaC1lZDI1NTE5AAAAIHV8K5j1UNZSmAl4Xq7Yp8Qe1nN74B5NA7UyZDvz0H4M\n"
        "---- END SSH2 PUBLIC KEY ----\n"
    )
    keys = Ssh2Key.parse(key_contents)
    assert len(keys) == 2
