#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Given EMK blob from Windows "1Password10.sqlite" database,
#   and user's primary account Master Password,
#   decrypts EMK blob to produce master encryption and HMAC keys
#

import optestlib

bin_emk = optestlib.get_binary('Enter EMK data (from config table) in base-64 or hex:  ')

password = raw_input("\nEnter the master password: ")

PT = optestlib.decrypt_emk(bin_emk, password)

enc_key = PT[0:32]
hmac_key = PT[32:]

optestlib.p_data('Master Enc Key', enc_key)
optestlib.p_str('(base-64)', optestlib.opb64e(enc_key))
optestlib.p_data('Master HMAC Key', hmac_key)
optestlib.p_str('(base-64)', optestlib.opb64e(hmac_key))

optestlib.p_str('Enc+HMAC together', optestlib.opb64e(enc_key+hmac_key))


