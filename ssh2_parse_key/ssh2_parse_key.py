"""Main module for ssh2_parse_key - provides Ssh2Key()"""
import base64
import re
import struct
import textwrap
from collections import OrderedDict

from classforge import Field
from classforge import StrictClass

SSH2_KEY_TYPES = ["public", "private"]
SSH2_KEY_ENCRYPTIONS = ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"]
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


class Ssh2Key(StrictClass):
    """
    Encapsulates an ssh public key

    An Ssh2Key object is immutable after creation.  Typically you would create
    Ssh2Key objects by using ``parse()`` or ``parse_file()`` class methods.

    :param key: The ssh key itself
    :type key: string
    :param type: is this a public or private key
    :type type: one of ["public", "private"]
    :param encryption: The encryption type of the key
    :type encryption: one of ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"]
    :param headers: Any headers for the key - eg Comment
    :type headers: OrderedDict

    """

    #: string - base64 encoded: The ssh key itself
    key = Field(type=str, required=True, mutable=False)
    #: string - one of ["public", "private"]: is this a public or private key
    type = Field(type=str, choices=SSH2_KEY_TYPES, default="public", mutable=False)
    #: one of ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"]: The encryption
    #: type of the key
    encryption = Field(
        type=str, choices=SSH2_KEY_ENCRYPTIONS, default="ssh-rsa", mutable=False,
    )
    #: OrderedDict: Any headers for the key - eg Comment
    headers = Field(type=OrderedDict, default={}, mutable=False)

    @classmethod
    def parse(cls, data):
        """
        Creates a set of Ssh2Key objects from a string of ssh key data

        Accepts a block of text containing SSH2 public keys (in either OpenSSH or
        SECSH format) and parses out SSH2 public keys returning them as Ssh2Key
        Objects.

        :param data: A multiline string of ssh key data in OpenSSH or SECSH format
        :type data: str
        :rtype: list ``Ssh2Key`` objects
        :raises: ValueError
        """
        lines = data.splitlines()  # break the input into lines
        keys = []  # the keys we have parsed
        inside_keyblock = False  # where we are
        keyblock = []
        keytype = ""
        pubpriv = ""

        for line in lines:
            if inside_keyblock:
                matches = KEY_BOUNDARY_PATTERN.match(line)
                if matches:
                    if matches.group("beginend") == "END":
                        inside_keyblock = False  # no longer within a keyblock
                        if keytype == matches.group(
                            "keytype",
                        ) and pubpriv == matches.group("pubpriv"):
                            if keytype in ["OPENSSH", "DSA", "EC", "RSA"]:
                                key = cls._parse_openssh(keyblock, keytype, pubpriv)
                            elif keytype == "SSH2":
                                key = cls._parse_secsh(keyblock, pubpriv)
                            else:
                                raise ValueError(
                                    f"Unrecognised type of ssh key {keytype}",
                                )
                            if key:
                                keys.append(key)
                else:
                    keyblock.append(line)
            else:
                # look for a keyblock start
                matches = KEY_BOUNDARY_PATTERN.match(line)
                if matches:
                    if matches.group("beginend") == "BEGIN":
                        keytype = matches.group("keytype")
                        pubpriv = matches.group("pubpriv")
                        inside_keyblock = True  # inside a new keyblock
                    continue

                # check for OpenSSH format -- all on one line
                matches = OPENSSH_PUBKEY_PATTERN.match(line)
                if matches:
                    keys.append(cls._parse_openssh_oneline(matches))

                else:
                    # raise ValueError("Unrecognised type of ssh key")
                    pass  # ignore for now

        if len(keys) == 0:
            raise ValueError("No valid ssh keys found")

        # return the assemblage of keys
        return keys

    @classmethod
    def parse_file(cls, filepath):
        """
        Creates a set of Ssh2Key objects from a file of ssh key data

        Accepts a block of text containing SSH2 public keys (in either OpenSSH or
        SECSH format) and parses out SSH2 public keys returning them as Ssh2Key
        Objects.

        :param filepath: A pathname of a file containing ssh key data
        :type filepath: str
        :rtype: list ``Ssh2Key`` objects
        :raises: ValueError
        """
        with open(filepath, "r") as f:
            data = f.read()
            return cls.parse(data)

    @classmethod
    def _parse_openssh_oneline(cls, matches):
        """Build a openssh public key from regex match components."""
        key = matches.group("key")
        encryption = matches.group("encryption")
        headers = OrderedDict([("Comment", matches.group("comment"))])
        return cls(key=key, type="public", encryption=encryption, headers=headers)

    @classmethod
    def _parse_openssh(cls, keyblock, keytype, pubpriv):
        """Decode an openssh keyblock into a key object."""
        raise ValueError("Cannot currently decode openssh format keyblocks")

    @classmethod
    def _parse_secsh(cls, keyblock, pubpriv):
        """Decode an secsh/RFC4716 keyblock into a key object."""
        if pubpriv != "PUBLIC":
            raise ValueError("Can only decode secsh public keys")
        headers, data, key = cls._initial_parse_keyblock(keyblock)
        current_position, encryption = cls._unpack_by_int(data, 0)
        encryption = encryption.decode()
        print(f"encryption='{encryption}'")
        return cls(key=key, type="public", encryption=encryption, headers=headers)

    @classmethod
    def _initial_parse_keyblock(cls, keyblock):
        headers = OrderedDict([("Comment", "")])  # default empty comment
        in_header = False
        header = ""
        value = ""
        index = 0
        for line in keyblock:
            if in_header:
                if line.match("\\$"):  # trailing backslash
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
    def _unpack_by_int(cls, data, current_position):
        """Returns a tuple with (location of next data field, contents of requested data field)."""
        # Unpack length of data field
        try:
            requested_data_length = struct.unpack(
                ">I", data[current_position : current_position + INT_LEN],  # noqa: E203
            )[0]
        except struct.error:
            raise ValueError("Unable to unpack %s bytes from the data" % INT_LEN)

        # Move pointer to the beginning of the data field
        current_position += INT_LEN
        remaining_data_length = len(data[current_position:])

        if remaining_data_length < requested_data_length:
            raise ValueError(
                "Requested %s bytes, but only %s bytes available."
                % (requested_data_length, remaining_data_length),
            )

        next_data = data[
            current_position : current_position + requested_data_length  # noqa: E203
        ]
        # Move pointer to the end of the data field
        current_position += requested_data_length
        return current_position, next_data

    def secsh(self):
        """
        Returns an SSH public key in SECSH format (as specified in RFC4716).
        Preserves headers and the order of headers.  Returned as a single
        string including newlines and with terminating newline.

        See http://tools.ietf.org/html/rfc4716

        :rtype: str
        """
        lines = []
        if self.type == "public":
            key_header_chunk = "SSH2 PUBLIC KEY"
        else:
            raise ValueError("Unable to output secsh format private keys")
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

    def rfc4716(self):
        """
        Returns an SSH public key in SECSH format (as specified in RFC4716).
        Preserves headers and the order of headers.  Returned as a single
        string including newlines and with terminating newline.

        Alias - ``rfc4716()`` just calls ``secsh()``

        See http://tools.ietf.org/html/rfc4716

        :rtype: str
        """
        return self.secsh()

    def openssh(self):
        """
        Returns an SSH public/private key in OpenSSH format. Preserves 'comment'
        field parsed from either SECSH or OpenSSH.  Returned as a single
        string including newlines and with terminating newline.

        :rtype: str
        """
        lines = []
        if self.type == "public":
            lines.append(" ".join([self.encryption, self.key, self.comment()]))
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
            raise ValueError("Unable to output openssh format private keys")
        lines.append("")  # force terminating newline

        # return the assembled string
        return "\n".join(lines)

    def comment(self):
        """
        Returns the comment header from a ssh key object.

        :rtype: str
        """
        if "Comment" in self.headers:
            return self.headers["Comment"]

    def subject(self):
        """
        Returns the subject header from a ssh key object.

        :rtype: str
        """
        if "Subject" in self.headers:
            return self.headers["Subject"]

    def _encode_header(self, data, header, value, limit):
        bits = textwrap.wrap(f"{header}: {value}", limit)
        last = bits.pop()
        for bit in bits:
            data.append(bit + "\\")
        data.append(last)


# end
