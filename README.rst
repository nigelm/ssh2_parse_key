================
SSH2 Key Parsing
================


.. image:: https://img.shields.io/pypi/v/ssh2_parse_key.svg
        :target: https://pypi.python.org/pypi/ssh2_parse_key

.. image:: https://img.shields.io/travis/nigelm/ssh2_parse_key.svg
        :target: https://travis-ci.com/nigelm/ssh2_parse_key

.. image:: https://readthedocs.org/projects/ssh2-parse-key/badge/?version=latest
        :target: https://ssh2-parse-key.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status




Parses ssh2 public keys in either openssh or RFC4716/Secsh formats and
converts to either format.

At this point any attempt to work with private keys will raise an exception.


* Free software: MIT license
* Documentation: https://ssh2-parse-key.readthedocs.io.


Features
--------

* Reads public keys of the following encryption types:-
    - ssh-rsa
    - ssh-dss
    - ecdsa-sha2-nistp256
    - ssh-ed25519
* Reads either Openssh or RFC4716 format public keys
* Can read input sets with either or both formats in
* Can output either format for any key


Usage
-----

To use SSH2 Key Parsing in a project::

    from ssh2_parse_key import Ssh2Key

    # although you can create the object from internal data the normal method
    # would be to use the parse() or parse_file() which return a list of Ssh2Key objects.
    # Ssh2Key objects are immutable.
    # Load one or more keys in either openssh or RFC4716 from a file
    keys = Ssh2Key.parse_file("/path/to/public_key")

    # alternatively
    data = Path("/path/to/public_key").read_text()
    keys = Ssh2Key.parse(data)

    # now those keys can be dealt with...
    for public_key in keys:
        print(f"This is a {key.type} key")
        print(f"It uses {key.encryption} encryption")
        print(f"comment = {key.comment}")
        print(f"subject = {key.subject}")

        print("RFC4716 format representation")
        print(key.rfc4716)

        print("OpenSSH representation")
        print(key.openssh)

Credits
-------

The package is strongly based on the perl `Parse::SSH2::PublicKey`_ module.

The class is built using Michael DeHaan's `ClassForge`_ object system.

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Parse::SSH2::PublicKey: https://metacpan.org/pod/Parse::SSH2::PublicKey
.. _ClassForge: https://classforge.io/
.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
