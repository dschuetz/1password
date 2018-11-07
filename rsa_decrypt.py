#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Takes RSA key as a JSON string (JWK-ish format):
#
#    { "alg": "RSA-OAEP", "d": "XcdvqfcqjGi1h5GloyVJKulotMPOf1iVHd5G0XG6ONnsXFfh3bpXJrfos8MT3rRqNcQmAbmUzDjZEDyUeCl_J8GmegxeeZ3X3Iiua6v0ecsjcdz9QAohcEWtza4XQlAcciZQGJqNDKzImXnErUXDHbQebGjEa3Z_b3DjZqfI-QH5DYDMh5W61L7Ky8_8kc54A9EtJupqtKZwYnBtazzLTcl82APkyQ71aN9kD-iO8qA3lAQGkUykRBa_8TF0tDCGgFfW7ijcGk06NGsYex9ir_n8fYZOP3LXahEMO5_3j4vIixmktFpI8IhtdQNvXqYir3JyB3WOmszr5XC4VasAYQ", "e": "AQAB", "key_ops": [ "decrypt" ], "kid": "qn8uimc4l7sofa26yivex24j7q", "kty": "RSA", "n": "xA6dAIu2_S9Ia_xRkodmvBv9w4pMyjE7FFAiXKTcQJS8d1RLkY82hwghBa6YK7V28_-S0Hfe2_NecesRMCpDf03kl1SClJkl8bJpJ0AwZFhvj6JO1JUZAj8o06OpgUCij_Jt8YSiu8bQIXgH5bEEkZ3oBx1OyozgqCo6JBa7cQVlv2LGV25YnqIbzOTof8YBZMNM0GuzPQQDxJUEB4ktmKekFjtDvHzAUmtMEgGYpbgXl4AmRAbHlYPpepSBplqXSrJfxVfEgftAJudjQsrMr_uVNX5TYGgFJDqUzkiXBXEUFy22GqcIArLLiOtvUwEU843wYpLtSPN-A20YLfSTCw", "p": "0It5RDblXwYnJg-xuBrww6bxNr11x8ILCEVojwuAaNFegAqwPHbUw4nekx5mML30HltVgg3i3bi0ITLdHVqvdy9zUetTsEhsYlk9Zq8ox6nGQ9qEa-Hnu4YCB5Uh5iHMBZyUlmjRUPh1V7NcyafzjgJSin8-Me_DKrHxdalU6y8", "q": "8Kuuf2mnoNK1skNuxJU38Q6HC6cq9JoHN1U5dYKIcAXd0B1wEqHGcbo8UyviftfdPRy2fomKu1-c0uWcOzBZmlV4SkQ-_TwxcFPgTVcrhuAESHERZIYJuIr6JENoD7iph_BGOF-ftVGBULT7fFRH47t0jPkfTolXeC2tLIsQbuU" } 

# then decrypts the given ciphertext.
#
# This is finicky. And still hasn't made its way into optestlib.
#

import json
import sys
import base64

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

from jwkest.jwk import RSAKey, load_jwks
from jwkest.jwe import JWE


import optestlib


#
# this ugly stuff is here because on some platforms (macOS), raw_input hangs
# after like 1024 bytes.
#
import termios, tty
old_tty_attr = termios.tcgetattr(sys.stdin)
new_tty_attr = old_tty_attr[:]
new_tty_attr[3] = new_tty_attr[3] & ~( tty.ICANON)
termios.tcsetattr(sys.stdin, tty.TCSANOW, new_tty_attr)

key_raw = raw_input("Enter RSA private key (as json, decrypted from keyset): ")

termios.tcsetattr(sys.stdin, tty.TCSANOW, old_tty_attr)


jwkj = '{"keys": [%s]}' % key_raw
jwk = json.loads(jwkj)

jwk = load_jwks(jwkj)[0]
RSA_Key = RSA.construct((jwk.n, jwk.e, jwk.d))

ct = optestlib.get_binary("\nEnter ciphertext (base-64 or hex): ")


cipher = PKCS1_OAEP.new(RSA_Key)
message = cipher.decrypt(ct)

print "\nDecrypted data:\n"
print message
