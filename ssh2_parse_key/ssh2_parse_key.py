"""Main module for `ssh2_parse_key` - provides `Ssh2Key()`"""

import base64
import os
import re
import struct
import textwrap
from collections import OrderedDict
from pathlib import Path
from re import Match
from typing import Self

import attr

SSH2_KEY_TYPES = ("public", "private")
SSH2_KEY_ENCRYPTIONS = ("ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519")
OPENSSH_PUBKEY_PATTERN = re.compile(
    r"""
            ^
            (?P<encryption>ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) # encryption
            \s+                                                             # space
            (?P<key>[A-Z0-9a-z/+=]+)                                        # key
            \s+                                                             # space
            (?P<comment>[^\n]*)                                             # comment
            """,
    re.VERBOSE,
)
KEY_BOUNDARY_PATTERN = re.compile(
    r"""
            ^
            ----[- ]                                                        # initial run
            (?P<beginend>BEGIN|END)                                         # beginend - BEGIN/END
            \s                                                              # space
            (?P<keytype>OPENSSH|SSH2|DSA|EC|RSA)                            # keytype
            \s                                                              # space
            (?P<pubpriv>PUBLIC|PRIVATE|ENCRYPTED\sPRIVATE)                  # pubpriv - PUBLIC/PRIVATE
            \s                                                              # space
            KEY                                                             # KEY
            [- ]----\s*                                                     # end run
            $
            """,
    re.VERBOSE,
)
HEADER_LINE_PATTERN = re.compile(
    r"""
            ^
            (?P<header>[A-Za-z0-9][A-Za-z0-9_-]*[A-Za-z0-9]):               # header name + colon
            \s*                                                             # space(s)
            (?P<value>.*)                                                   # value
            (?P<backslash>\\?)                                              # backslash
            $
            """,
    re.VERBOSE,
)
INT_LEN = 4


@attr.s(slots=True, frozen=True, kw_only=True)
class Ssh2Key:
    """Encapsulates an ssh public key

    An `Ssh2Key` object is immutable after creation.  Typically you would create
    `Ssh2Key` objects by using `parse()` or `parse_file()` class methods.

    Attributes:
        key: The ssh key itself, Base64 string
        type: one of `public` or `private`
        encryption: one of `ssh-rsa`, `ssh-dss`, `ecdsa-sha2-nistp256`, `ssh-ed25519`
        headers: Any headers for the key - eg Comment.

    """

    key: str = attr.ib()
    key_type: str = attr.ib(
        default="public",
        validator=attr.validators.in_(SSH2_KEY_TYPES),
    )
    encryption: str = attr.ib(
        default="ssh-rsa",
        validator=attr.validators.in_(SSH2_KEY_ENCRYPTIONS),
    )
    headers = attr.ib(
        type=OrderedDict,
        default=attr.Factory(OrderedDict),
    )  # type: OrderedDict[str, str]

    @classmethod
    def parse(cls: type[Self], data: str) -> list[Self]:  # noqa: PLR0912
        """Creates a set of `Ssh2Key` objects from a string of ssh key data

        Accepts a block of text containing SSH2 public keys (in either OpenSSH or
        SECSH format) and parses out SSH2 public keys returning them as `Ssh2Key`
        Objects.

        Arguments:
            data: A multiline string of ssh key data in OpenSSH or SECSH format

        Raises:
            ValueError: Unrecognised type of ssh key
            ValueError: No valid ssh keys found

        Returns:
            keys: A list of  `Ssh2Key` objects

        """
        lines = data.splitlines()  # break the input into lines
        keys: list[Self] = []
        inside_keyblock = False  # where we are
        keyblock: list[str] = []
        keytype = ""
        pubpriv = ""

        for line in lines:
            matches = KEY_BOUNDARY_PATTERN.match(line)
            if inside_keyblock:
                if matches and matches.group("beginend") == "END":
                    inside_keyblock = False  # no longer within a keyblock
                    if keytype == matches.group("keytype") and pubpriv == matches.group(
                        "pubpriv",
                    ):
                        if keytype in ["OPENSSH", "DSA", "EC", "RSA"]:
                            keys.append(cls._parse_openssh(keyblock, keytype, pubpriv))
                        elif keytype == "SSH2":
                            keys.append(cls._parse_secsh(keyblock, pubpriv))
                        else:
                            msg = f"Unrecognised type of ssh key {keytype}"
                            raise ValueError(
                                msg,
                            )
                    keyblock = []  # fresh keyblock for next key
                else:
                    keyblock.append(line)
            elif matches and matches.group("beginend") == "BEGIN":
                keytype = matches.group("keytype")
                pubpriv = matches.group("pubpriv")
                inside_keyblock = True  # inside a new keyblock
            else:
                # check for OpenSSH format -- all on one line
                matches = OPENSSH_PUBKEY_PATTERN.match(line)
                if matches:
                    keys.append(cls._parse_openssh_oneline(matches))
                else:
                    # raise ValueError("Unrecognised type of ssh key")
                    pass  # ignore for now

        if len(keys) == 0:
            msg = "No valid ssh keys found"
            raise ValueError(msg)

        # return the assemblage of keys
        return keys

    @classmethod
    def parse_file(cls: type[Self], filepath: str | os.PathLike[str]) -> list[Self]:
        """Creates a set of `Ssh2Key` objects from a file of ssh key data

        Accepts a block of text containing SSH2 public keys (in either OpenSSH or
        SECSH format) and parses out SSH2 public keys returning them as `Ssh2Key`
        Objects.

        Arguments:
            filepath: Pathname of a file of ssh key data in OpenSSH or SECSH format

        Raises:
            IOError: From underlying open/read
            ValueError: Unrecognised type of ssh key
            ValueError: No valid ssh keys found

        Returns:
            keys: A list of  `Ssh2Key` objects
        """
        return cls.parse(Path(filepath).read_text())

    @classmethod
    def _parse_openssh_oneline(cls: type[Self], matches: Match) -> Self:
        """Build a openssh public key from regex match components."""
        key = matches.group("key")
        encryption = matches.group("encryption")
        headers = OrderedDict([("Comment", matches.group("comment"))])
        return cls(key=key, key_type="public", encryption=encryption, headers=headers)

    @classmethod
    def _parse_openssh(cls: type[Self], keyblock: list[str], keytype: str, pubpriv: str) -> Self:  # noqa: ARG003
        """Decode an openssh keyblock into a key object."""
        msg = "Cannot currently decode openssh format keyblocks"
        raise ValueError(msg)

    @classmethod
    def _parse_secsh(cls: type[Self], keyblock: list[str], pubpriv: str) -> Self:
        """Decode an secsh/RFC4716 keyblock into a key object."""
        if pubpriv != "PUBLIC":
            msg = "Can only decode secsh public keys"
            raise ValueError(msg)
        headers, data, key = cls._initial_parse_keyblock(keyblock)
        current_position, encryption_bytes = cls._unpack_by_int(data, 0)
        encryption = encryption_bytes.decode()
        return cls(key=key, key_type="public", encryption=encryption, headers=headers)

    @classmethod
    def _initial_parse_keyblock(cls: type[Self], keyblock: "list[str]") -> tuple:
        headers = OrderedDict([("Comment", "")])  # default empty comment
        in_header = False
        header = ""
        value = ""
        index = 0
        for line in keyblock:
            if in_header:
                if re.match(r"\\$", line):  # trailing backslash
                    value = value + line[:-1]
                else:
                    value = value + line
                    headers[header] = value
                    in_header = False
                    header = ""
                    value = ""
            else:
                matches = HEADER_LINE_PATTERN.match(line)
                if matches:
                    header = matches.group("header")
                    value = matches.group("value")
                    if matches.group("backslash") == "\\":
                        in_header = True
                    else:
                        headers[header] = value
                        in_header = False
                        header = ""
                        value = ""
                else:
                    break  # all out of headers
            index = index + 1
        data = base64.b64decode("".join(keyblock[index:]))
        key = base64.b64encode(data).decode()  # build clean version without spaces etc
        return (headers, data, key)

    @classmethod
    def _unpack_by_int(cls: type[Self], data: bytes, current_position: int) -> tuple[int, bytes]:
        """Returns a tuple with (location of next data field, contents of requested data field)."""
        # Unpack length of data field
        try:
            requested_data_length = struct.unpack(
                ">I",
                data[current_position : current_position + INT_LEN],
            )[0]
        except struct.error as err:
            raise ValueError("Unable to unpack %s bytes from the data" % INT_LEN) from err

        # Move pointer to the beginning of the data field
        current_position += INT_LEN
        remaining_data_length = len(data[current_position:])

        if remaining_data_length < requested_data_length:
            msg = f"Requested {requested_data_length} bytes, but only {remaining_data_length} bytes available."
            raise ValueError(
                msg,
            )

        next_data = data[current_position : current_position + requested_data_length]
        # Move pointer to the end of the data field
        current_position += requested_data_length
        return current_position, next_data

    def secsh(self: Self) -> str:
        """Returns an SSH public key in SECSH format (as specified in RFC4716).

        Preserves headers and the order of headers.  Returned as a single
        string including newlines and with terminating newline.

        See http://tools.ietf.org/html/rfc4716

        Raises:
            ValueError: Unable to output secsh format private keys

        Returns:
            string: Single secsh key as a string including newlines and with terminating newline.
        """
        lines: "list[str]" = []
        if self.key_type == "public":
            key_header_chunk = "SSH2 PUBLIC KEY"
        else:
            msg = "Unable to output secsh format private keys"
            raise ValueError(msg)
            key_header_chunk = "SSH2 ENCRYPTED PRIVATE KEY"

        # add the wrapping header
        lines.append(f"---- BEGIN {key_header_chunk} ----")

        # add the headers, if any
        if len(self.headers):
            for header, value in self.headers.items():
                self._encode_header(lines, header, value, 74)

        # add the key content
        lines.extend(textwrap.wrap(self.key, 70))

        # add the wrapping footer
        lines.append(f"---- END {key_header_chunk} ----")
        lines.append("")  # force terminating newline

        # return the assembled string
        return "\n".join(lines)

    def rfc4716(self: Self) -> str:
        """Returns an SSH public key in SECSH format (as specified in RFC4716).

        Preserves headers and the order of headers.  Returned as a single
        string including newlines and with terminating newline.

        Alias - ``rfc4716()`` just calls ``secsh()``

        See http://tools.ietf.org/html/rfc4716

        Raises:
            ValueError: Unable to output secsh format private keys

        Returns:
            string: Single secsh key as a string including newlines and with terminating newline.
        """
        return self.secsh()

    def openssh(self: Self) -> str:
        """Returns an SSH public/private key in OpenSSH format. Preserves 'comment'

        field parsed from either SECSH or OpenSSH.  Returned as a single
        string including newlines and with terminating newline.

        Raises:
            ValueError: Unable to output openssh format private keys

        Returns:
            string: Single openssh key as a string including newlines and with terminating newline.
        """
        lines: list[str] = []
        if self.key_type == "public":
            lines.append(f"{self.encryption} {self.key} {self.comment()}")
        else:
            # ## Initial code to deal with private keys not used
            # # private key - obviously!
            # # add the wrapping header
            # lines.append(f"---- BEGIN {self.encryption} PRIVATE KEY ----")
            #
            # # add the headers, if any
            # if len(self.headers):
            #     for header, value in self.headers.items():
            #         self._encode_header(lines, header, value, 64)
            #
            # # add the key content
            # lines.extend(textwrap.wrap(self.key, 64))
            #
            # # add the wrapping footer
            # lines.append(f"---- END {self.encryption} PRIVATE KEY ----")
            msg = "Unable to output openssh format private keys"
            raise ValueError(msg)
        lines.append("")  # force terminating newline

        # return the assembled string
        return "\n".join(lines)

    def comment(self: Self) -> str:
        """Returns the comment header from a ssh key object.

        Returns:
            string: Comment field or an empty string.
        """
        if "Comment" in self.headers:
            return self.headers["Comment"]
        return ""

    def subject(self: Self) -> str | None:
        """Returns the subject header from a ssh key object.

        Returns:
            string: Subject field or `None`.
        """
        if "Subject" in self.headers:
            return self.headers["Subject"]
        return None

    def _encode_header(
        self: Self,
        data: "list[str]",
        header: str,
        value: str,
        limit: int,
    ) -> None:
        bits = textwrap.wrap(f"{header}: {value}", limit)
        last = bits.pop()
        for bit in bits:
            data.append(bit + "\\")
        data.append(last)


# end
