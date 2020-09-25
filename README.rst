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


Status
------

Still in initial stages, while I get used to some of the tooling, so
some things like the documentation are not right (both content and
some of the issues around how it is generated).  Currently not feeding
to `readthedocs` despite what it says above...


Credits
-------

The package is strongly based on the perl `Parse::SSH2::PublicKey`_ module.

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _`Parse::SSH2::PublicKey`: https://metacpan.org/pod/Parse::SSH2::PublicKey
.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
