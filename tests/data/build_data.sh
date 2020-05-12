#!/bin/sh
#
# Generate a set of test keys using the openssh ssh-keygen, one
# key of each type, default lengths, with a default comment and no
# passphrase.
# Additionally generate a converted RFC4716 key and public key for each.
#
# This must be run from within the data directory.
#
for keytype in dsa ecdsa ed25519 rsa; do
    # generating in old PEM format (other than ed25519 which has no old format)
    ssh-keygen -f test_key_${keytype} -N '' -m PEM -t ${keytype} -C "Test ssh key in ${keytype} format"
    ##  ssh-keygen -e -f test_key_${keytype} -m RFC4716 >test_key_${keytype}_rfc4716
    ssh-keygen -e -f test_key_${keytype}.pub -m RFC4716 >test_key_${keytype}_rfc4716.pub
done

# end
