#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# * Takes an AES-256 key, IV, and ciphertext.
# * Presumes the last 16 bytes of the ciphertext are the 256-bit GCM tag.
# * Decrypts and verifies using AES-GCM
# * Prints plaintexgt in ASCII and Hex
#

import optestlib

key = optestlib.get_binary("Enter AES-256 key (hex or base-64 encoded)\n --> ")
iv = optestlib.get_binary("Enter IV (hex or base-64): ")
ct = optestlib.get_binary("Enter ciphertext (hex or base-64): ")

PT = optestlib.dec_aes_gcm(ct[:-16], key, iv, ct[-16:])

print "\n"

optestlib.p_str('Plaintext', PT)
optestlib.p_data('Plaintext, hex', PT)
