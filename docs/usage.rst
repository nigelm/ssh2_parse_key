=====
Usage
=====

To use SSH2 Key Parsing in a project::

    import ssh2_parse_key

    # although you can create the object from internal data
    # the normal method would be to use the parse() or parse_file()
    # which return a list of Ssh2Key objects.
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
