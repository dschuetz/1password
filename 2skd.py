#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Given email, Secret Key, Master Password, and elements from "enc_sym_key"
#   from the primary account's first keyset ("encrypted_by = mp"),
#   computes 1Password 2SKD result for MUK and SRP-X
#

import optestlib

secret_key = raw_input("\nEnter the account's Secret Key (A3-xxx....): ").upper()

password = raw_input("\nEnter the master password:")

email = raw_input("\nEnter the email address: ")

p2s = optestlib.get_binary("\nEnter the 'p2s' parameter (salt, base-64 or hex encoded): ")

p2c = raw_input("\nEnter the 'p2c' parameter (iterations count): ")
p2c = int(p2c)

algo = raw_input("\nEnter the 'alg' parameter\n  (PBES2g-HS256 for MUK, SRPg-4096 for SRP-x) (note: case sensitive): ")

print "\n"

muk = optestlib.compute_2skd(secret_key, password, email, p2s, p2c, algo)

optestlib.p_str('\nBase-64 Encoded result:', optestlib.opb64e(muk))

