#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Takes a 64-byte key (256-bit AES key + 256-bit HMAC key), and
#   a 1Password "opdata01" format binary. 
#
# Verifies the HMAC signature on the opdata vault, and if it is valid,
#   decrypts the data.
#

import optestlib

key = optestlib.get_binary('Enter 64-byte key (AES + HMAC) (hex or base-64): ')

op_data = optestlib.get_binary('Enter OPDATA binary (hex or base-64): ')

optestlib.decrypt_opdata(op_data, key[0:32], key[32:64])

