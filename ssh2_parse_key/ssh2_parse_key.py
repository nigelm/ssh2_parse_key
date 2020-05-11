"""Main module."""
import re
from collections import OrderedDict

from classforge import Field
from classforge import StrictClass

SSH2_KEY_TYPES = ["public", "private"]
SSH2_KEY_ENCRYPTIONS = ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"]
OPENSSH_PUBKEY_PATTERN = re.compile(
    r"""
            (?P<encryption>ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) # encryption
            \s+                                                             # space
            (?P<key>[A-Z0-9a-z/+=]+)                                        # key
            \s+                                                             # space
            (?P<comment>[^\n]*)                                             # comment
            """,
    re.VERBOSE,
)


class Ssh2Key(StrictClass):
    key = Field(type=str, required=True)
    type = Field(type=str, choices=SSH2_KEY_TYPES, default="public")
    encryption = Field(type=str, choices=SSH2_KEY_ENCRYPTIONS, default="ssh-rsa")
    headers = Field(type=OrderedDict, default={})

    @classmethod
    def parse(cls, data):
        """
        Accepts a block of text and parses out SSH2 public keys in both OpenSSH and SECSH format.
        Class method to be used instead of new().
        """
        headers = OrderedDict([("Comment", "")])  # default empty comment

        # check for OpenSSH format -- all on one line
        matches = OPENSSH_PUBKEY_PATTERN.match(data)
        if matches:
            key = matches.group("key")
            type = "public"
            encryption = matches.group("encryption")
            headers["Comment"] = matches.group("comment")
        else:
            raise ValueError("Unrecognised type of ssh key")
        return [cls(key=key, type=type, encryption=encryption, headers=headers)]

    @classmethod
    def parse_file(cls, filepath):
        """Convenience method which opens a file and calls parse() on the contents."""
        with open(filepath, "r") as f:
            data = f.read()
            return cls.parse(data)

    def secsh(self):
        """
        Returns an SSH public key in SECSH format (as specified in RFC4716).
        Preserves headers and the order of headers.

        See http://tools.ietf.org/html/rfc4716
        """
        # lines = []
        # if self.type == "public":
        #     lines.append ("---- BEGIN SSH2 PUBLIC KEY ----")
        #     my @headers = @{$self->header_order()};
        #     if ( scalar(@headers) ) {
        #         for my $h ( @headers ) {
        #             $str .= join("\\", split(//, _chop_long_string(
        #                     $h . ': ' . $self->headers->{$h}, 70 ))) . "";
        #         }
        #     }
        #     $str .= _chop_long_string( $self->key, 70 ) . "";
        #     $str .= "---- END SSH2 PUBLIC KEY ----";
        pass

    def openssh(self):
        """
        Returns an SSH public key in OpenSSH format. Preserves 'comment' field
        parsed from either SECSH or OpenSSH.  Does not include trailing newline.
        """
        return " ".join([self.encryption, self.key, self.comment])

    def comment(self):
        return self.headers["Comment"]

    def subject(self):
        return self.headers["Subject"]


# end
