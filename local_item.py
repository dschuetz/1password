#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Decrypts 1Password item from "old style" local vault 
#   (OPVault, not cloud-baed B5 system)
# 
# Takes four keys, derived from the Master Password and encrypted random data
#    (see local_keys.py):
# 
#   * master encryption key
#   * master HMAC key
#   * overview encryption key
#   * overview HMAC key
# 
# Then accepts encrypted data
#
#   * encrypted item overview data (from items table)
#   * encrypted item key data (from items table)
#   * encrypted item details (from item_details table)
#
# Script uses overview key to decrypt and display item overview,
# master key to decrypt item key, and
# item key to decrypt and display item details.
#

import optestlib


m_key = optestlib.get_binary("Enter master encryption key (base-64 or hex encoded): ")
m_hmac = optestlib.get_binary("Enter master HMAC key (base-64 or hex encoded): ")
o_key = optestlib.get_binary("Enter overview encryption key (base-64 or hex encoded): ")
o_hmac = optestlib.get_binary("Enter master HMAC key (base-64 or hex encoded): ")

o_data = optestlib.get_binary('Enter overview data (base-64 or hex): ')
i_key_data_enc = optestlib.get_binary('Enter item key data (base-64 or hex): ')
i_data = optestlib.get_binary('Enter item detail data (base-64 or hex): ')

print "\n* Decrypting item overview\n"

o_pt = optestlib.decrypt_opdata(o_data, o_key, o_hmac)

optestlib.p_str('Item Overview', o_pt)

print "\n* Decrypting item keys\n"

i_key_data = optestlib.decrypt_verify_cbc(i_key_data_enc, m_key, m_hmac)
i_key = i_key_data[0:32]
i_hmac = i_key_data[32:]

optestlib.p_data('Item Key', i_key)
optestlib.p_data('Item HMAC', i_hmac)


print "\n* Decrypting item details\n"

i_pt = optestlib.decrypt_opdata(i_data, i_key, i_hmac)
optestlib.p_str('Item Details', o_pt)

