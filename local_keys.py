#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Generates master and overview keys for local 1Password vaults (using older
#   vault system, not newer cloud vaults).
#
# Takes information from "profiles" table in OnePassword database,
#   and enc_login data from "accounts" table in B5 datatbase (if present).
#

import optestlib


password = raw_input("\nEnter the master password: ")

print "Enter data from the 'profiles' table: "

iterations = raw_input("\n  Enter the iterations parameter: ")
iterations = int(iterations)

salt = optestlib.get_binary("  Enter the salt (hex or base64 encoded): ")

enc_master_key_data = optestlib.get_binary("  Enter master_key_data (hex or base64): ")

enc_overview_key_data = optestlib.get_binary("  Enter overview_key_data (hex or base64): ")

mk, mk_hmac, ok, ok_hmac = optestlib.get_local_vault_keys(password, salt, enc_master_key_data, enc_overview_key_data)

print "\n* Derived/Decrypted/Derived Vault Keys"

optestlib.p_data('Master Key', mk, dump=False)
optestlib.p_data('Master HMAC Key', mk_hmac, dump=False)
optestlib.p_data('Overview Key', ok, dump=False)
optestlib.p_data('Overview HMAC Key', ok_hmac, dump=False)

print "\n(Base-64 versions for convenience:"

optestlib.p_str('Master key', optestlib.opb64e(mk))
optestlib.p_str('Master HMAC key', optestlib.opb64e(mk_hmac))
optestlib.p_str('Overview key', optestlib.opb64e(ok))
optestlib.p_str('Overview HMAC key', optestlib.opb64e(ok_hmac))


enc_login_data = optestlib.get_binary("\nEnter encrypted login data (from accounts table) (hex / base64): ")


PT = optestlib.decrypt_opdata(enc_login_data, mk, mk_hmac)

optestlib.p_str('Decrypted enc_login', PT)



