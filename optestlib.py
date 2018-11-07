#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Library of functions called by all the other tools here.
#
# Not exactly a "clean" library -- many have debugging functions built
#   in that make them very noisy. And there are certainly inconsistencies
#   between functions regarding debug output, variable naming, calling 
#   conventions, style, and just general quality.
# 


from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.Util.Padding import pad, unpad

from jwkest.jwk import RSAKey, load_jwks
from jwkest.jwe import JWE
from Crypto.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

import hashlib,hmac

import sys, base64, binascii, re, json, struct, termios, tty


DEBUG = 1


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
#
# basic crypto stuff - wrappers around PyCryptoDome, etc.
#
# * encrypt/decrypt AES-GCM with 128-bit GCM tag
# * encrypt/decrypt AES-CBC with HMAC-SHA256 tag
# * encrypt/decrypt 1Password "opdata" structure 
#   * AES-CBC with HS-256 tag
#
# All use 256-bit keys
#
# Should probably pull RSA stuff out of the other scripts
# and add them here. 
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


#
# Encrypt PT with AES-GCM using key and iv
#   * If iv not provided, one will be created
#   * Returns IV, and Ciphertext with GCM tag appended
#   * Length of GCM tag hard-coded to 16 bytes
#
def enc_aes_gcm(pt, key, iv=None):
    if iv == None:
        iv = get_random_bytes(16)

    C = AES.new(key, AES.MODE_GCM, iv, mac_len=16)
    CT, tag = C.encrypt_and_digest(pt)

    return iv, CT+tag


#
# Decrypt CT with AES-GCM using key and iv
#   * If iv not provided, one will be created
#   * Verifies GCM tag 
#     - if verification fails, program will terminate with error
#   * Length of GCM tag hard-coded to 16 bytes
#
def dec_aes_gcm(ct, key, iv, tag):
    C = AES.new(key, AES.MODE_GCM, iv, mac_len=16)
    PT = C.decrypt_and_verify(ct, tag)

    return PT


#
# Encrypt plaintext with AES-CBC using given key and iv
#   * if iv not provided, one will be created
#   * Pads plaintext to 16-byte boundary if necessary
#   * computes HMAC-SHA256 tag using hmac_key
#     - computes across IV + ciphertext
#     - appends tag to ciphertext
#
# Returns:
#   * iv + ciphertext + tag
#
def encrypt_tag_cbc(pt, iv, key, hmac_key):
    if iv == None:
        iv = get_random_bytes(16)

    pt = pad(pt, 16)
    C = AES.new(key, AES.MODE_CBC, iv)
    ct = C.encrypt(pt)

    hm = hmac.new(hmac_key, iv+ct, digestmod=hashlib.sha256)
    ht = hm.digest()

    out = iv + ct + ht
    
    return out

#
# Decrypt ciphertext with AES-CBC using given
#   * takes structure of IV + CT + HMAC-Tag
#   * first computes HMAC-SHA256 of "IV+CT"
#   * if doesn't match provided tag, terminates program with error
#   * otherwise, decrypts using AES-CBC
#   * removes any padding to 16-byte boundary
#
# Returns plaintext
#
def decrypt_verify_cbc(iv_ct_tag, key, hmac_key):
    
    msg = iv_ct_tag[0:-32]

    iv = iv_ct_tag[0:16]
    ct = iv_ct_tag[16:-32]
    tag = iv_ct_tag[-32:]

    hm = hmac.new(hmac_key, msg, digestmod=hashlib.sha256)
    ht = hm.digest()

    if ht != tag:
        print("HMAC tag doesn't match!")
        sys.exit(1)

    C = AES.new(key, AES.MODE_CBC, iv)
    
    PT = C.decrypt(ct)
    PT = unpad(PT, 16)

    return PT


#
# Encrypts data into an opdata format structure
#   * Takes 256-bit encryption key and HMAC key
#   * If iv not provided, one will be generated at random
#   * If padding is not provided, padding will be generated at random
#   * encrypts padded payload with AES-CBC
#   * Computes HMAC-SHA256 authentication tag:
#     - Header + IV + Padding + Plaintext
#
# Returns binary opdata structure:
#   * header (opdata01 + payload length)
#   * IV
#   * Ciphertext
#   * HMAC tag
#
def encrypt_opdata(payload, enc_key, hmac_key, iv=None, padding=None):
    p_debug('\n** Encrypting opdata01 structure')

    header = 'opdata01' + struct.pack('<Q', len(payload))
    p_str('PT length', len(payload))


    if padding == None:
        pad_len = 16 - (len(payload) % 16)
        padding = get_random_bytes(pad_len)
    p_data('Padded plaintext', padding + payload)

    if iv == None:
        iv = get_random_bytes(16)
    p_data('AES-CBC Key', enc_key, dump=False)

    C = AES.new(enc_key, AES.MODE_CBC, iv)
    CT = C.encrypt(padding + payload)

    p_data('Header', header)
    p_data('IV', iv, dump=False)
    p_data('Ciphertext', CT, dump=False)

    msg = header + iv + CT

    hm = hmac.new(hmac_key, msg, digestmod=hashlib.sha256)
    ht = hm.digest()

    p_data('HMAC-SHA256 Key', hmac_key, dump=False)
    p_data('Computed HMAC', ht, dump=False)
    msg += ht

    p_data('Final opdata', msg)
    p_debug('\n')
    return msg


#
# Decrypts data from an opdata format structure
#   * Takes opdata structure, 256-bit encryption key and HMAC key 
#   * Extracts payload length and IV
#   * Computes HMAC-SHA256 digest across entire structure
#     - header + iv + ciphertext
#   * If computed tag doesn't match tag in structure, exits with error
#   * Otherwise, decrypts ciphertext using provided key and AES-CBC
#
# Returns decrypted plaintext with padding removed
#
def decrypt_opdata(opdata, enc_key, hmac_key):
    p_debug('\n** Decrypting OPDATA structure')
    p_data('raw opdata', opdata)
    if opdata[0:8] != 'opdata01':
        print "ERROR - opdata01 block missing 'opdata01' header. Quitting."
        sys.exit(1)
    p_data('Header', opdata[0:8], opdata[0:8])

    pt_len   = struct.unpack('<Q', opdata[8:16])[0]
    p_data('PT length', opdata[8:16], pt_len)

    op_header = opdata[0:16]

    iv = opdata[16:32]
    p_data('IV', iv)

    ct = opdata[32:-32]  # header + iv: 32 bytes; trailing HMAC tag: 32 bytes
    p_data('CT', ct)

    p_debug('CT length (padded): %d' % (len(ct)))

    ht = opdata[-32:]
    p_data('HMAC digest', ht)

    p_debug("\nVerifying HMAC tag")
    p_data('OPdata Msg', opdata[0:-32])   # don't HMAC the provided HMAC tag
    p_data('HMAC key', hmac_key)
    hm = hmac.new(hmac_key, opdata[0:-32], digestmod=hashlib.sha256)
    p_data('Computed HMAC', hm.digest())

    if hm.digest() != ht:
        print("ERROR - Computed HMAC does not match provided value.")
        sys.exit(1)
    else:
        print("HMAC signature verified.")

    C = AES.new(enc_key, AES.MODE_CBC, iv)
    PT = C.decrypt(ct)

    start_at = len(ct) - pt_len

    PT=PT[start_at:] # first x bytes are random padding

    p_debug("\n\n")
    p_debug("*** decrypted opdata")
    p_data('Plaintext', PT)
    p_debug('\n')

    return PT



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
#
# 1Password specific functionality
#
# * Compute 2SKD for generating MUK and SRP-X authenticator
# * Decrypt Windows EMK data
# * Generate and decode keys for local private vaults
#
# Some of these really don't ever get used except by a single
#   demonstration script. The line between a useful library
#   and just a convenient place to shove things is a little
#   blurry here. Whatever. :)
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#
# Implements the Two-Secret Key Derivation process (2SKD)
# Takes the user's:
#   * Secret Key (Account Key)
#   * Master Password
#   * Salt (p2salt)
#   * Iterations count (p2c)
#   * Algorithm (PBES2g-HS256, SRPg-4096)
#
# Returns the result (used for either MUK or SRP-X)
#
def compute_2skd(sk, password, email, p2salt, iterations, algorithm):
    p_debug("** Computing 2SKD\n")

    version = sk[0:2]
    account_id = sk[3:9]
    secret = re.sub('-', '', sk[10:])
    email = email.lower() # simple hack...not doing "proper" normalizaiton...

    email = str.encode(str(email))
    version = str.encode(str(version))

    secret = str.encode(str(secret))
    account_id = str.encode(str(account_id))

    algorithm = str.encode(str(algorithm))

    p_str('Password', password)
    p_str('Email', email)
    p_str('Secret Key', sk)
    p_str('   Version', version)
    p_str('   AcctID', account_id)
    p_str('   Secret', secret)
    p_str('Algorithm', algorithm)
    p_str('Iterations (p2c)', iterations)
    p_str('Salt (p2s)', opb64e(p2salt))

    p_data('Salt (decoded)', p2salt, dump=False)

    hkdf_pass_salt = HKDF(p2salt, 32, email, SHA256, 1, algorithm)

    p_debug('\nHKDF(ikm=p2s, len=32, salt=email, hash=SHA256, count=1, info=algorithm)')
    p_data('HKDF out: pass salt', hkdf_pass_salt, dump=False)

    password = str.encode(str(password))
    password_key = hashlib.pbkdf2_hmac('sha256', password, hkdf_pass_salt, iterations, dklen=32)

    p_debug('\nPBKDF2(sha256, password, salt=HKDF_salt, iterations=p2c, 32 bytes)')
    p_data('Derived password key', password_key, dump=False)

    p_debug('\nHKDF(ikm=secret, len=32, salt=AcctID, hash=SHA256, count=1, info=version)')
    hkdf_key = HKDF(secret, 32, account_id, SHA256, 1, 'A3')
    p_data('HKDF out: secret key', hkdf_key, dump=False)

    final_key = ''

    for x in range(0,32): 

        a = ord(password_key[x])
        b = ord(hkdf_key[x])
        c = a^b
        final_key = final_key + chr(c)

    p_debug('\nXOR PBKDF2 output and SecretKey HKDF output')
    p_data('Final 2SKD out', final_key, dump=False)

    return final_key

#
# Decrypts the given Windows Encrypted Master Key (EMK) structure,
#    using the provided Master Password.
#
def decrypt_emk(bin_emk, password):
    print "*** EMK Structure from DB\n"

    p_data('RAW HEX', bin_emk)
    print "\n\n"

    iterations = struct.unpack('<I', bin_emk[0:4])[0]
    p_data('Iterations', bin_emk[0:4], iterations)

    salt_len   = struct.unpack('<I', bin_emk[4:8])[0]
    if salt_len != 16:
        print "huh. haven't seen a salt length of %d before. quitting." % salt_len
        sys.exit(1)
    salt = bin_emk[8:24]
    p_data('Salt len', bin_emk[4:8], salt_len)
    p_data('Salt', bin_emk[8:24])

    raw_key = hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen=64)

    print "*** Encryption Key and HMAC Key, derived from password:"
    p_data('Raw derived key', raw_key)
    emk_enc_key = raw_key[0:32]
    emk_hmac_key = raw_key[32:64]
    p_data("Derived enc key",emk_enc_key)
    p_data("Derived hmac key",emk_hmac_key)

    opdata = bin_emk[28:]

    dec_data = decrypt_opdata(opdata, emk_enc_key, emk_hmac_key)

    return dec_data

#
# Generate and encrypt OnePassword key data for local private vaults
# Requires:
#   * User's Master Password
#   * A salt for the password derivation process
#   * Random data, IV, and Padding for both overview and master keys
#
# Computes, and returns a structure of:
#   * private vault master key
#   * master hmac_key
#   * overview key
#   * overview hmac_key
#   * encrypted master_key_data
#   * encrpted overview_key_data
#
# will probably fail unpredictably if any of the required parameters
#   are missing
#
def gen_local_vault_keys(password, salt, mk_d, mk_iv, mk_p, ok_d, ok_iv,ok_p):
    p_debug('\n** Generating MasterKey (MK) and OverviewKey (OK) profile info')

    iter = 100000

    p_data('Salt', salt, dump=False)

    raw_key = hashlib.pbkdf2_hmac('sha512', password, salt, iter, dklen=64)

    op_kek_mk = raw_key[0:32]
    op_kek_hmac = raw_key[32:64]
    p_data('Derived key', op_kek_mk)
    p_data('Derived HMAC key', op_kek_hmac)

    enc_master_key = encrypt_opdata(mk_d, op_kek_mk, op_kek_hmac,
        iv=mk_iv, padding=mk_p)
   
    h_raw = SHA512.new(mk_d).digest()
    op_mk = h_raw[0:32]
    op_mk_hmac = h_raw[32:64]

    p_data('Priv vault MK', op_mk)
    p_data('Priv vault MK HMAC', op_mk_hmac)


    enc_overview_key = encrypt_opdata(ok_d, op_kek_mk, op_kek_hmac,
        iv=ok_iv, padding=ok_p)

    h_raw = SHA512.new(ok_d).digest()
    op_ok = h_raw[0:32]
    op_ok_hmac = h_raw[32:64]

    p_data('Priv vault OK', op_ok)
    p_data('Priv vault OK HMAC', op_ok_hmac)

    out = {'master_key': op_mk, 'master_key_hmac': op_mk_hmac, 
      'overview_key': op_ok, 'overview_key_hmac': op_ok_hmac,
      'enc_master_key_data': enc_master_key, 
      'enc_overview_key_data': enc_overview_key}

    return out


#
# Given the user's master password, information from the
#   local vault "profiles" table (salt, encrypted master key data
#   and overview key data), generates the master and overview
#   encryption and hmac keys.
#
def get_local_vault_keys(password, salt, e_mk_d, e_ok_d):
    iter = 100000
    p_data('Salt', salt, dump=False)

    raw_key = hashlib.pbkdf2_hmac('sha512', password, salt, iter, dklen=64)

    op_kek_mk = raw_key[0:32]
    op_kek_hmac = raw_key[32:64]
    p_data('Derived key', op_kek_mk)
    p_data('Derived HMAC key', op_kek_hmac)

    master_key_data = decrypt_opdata(e_mk_d, op_kek_mk, op_kek_hmac)

    h_raw = SHA512.new(master_key_data).digest()
    op_mk = h_raw[0:32]
    op_mk_hmac = h_raw[32:64]

    p_data('Priv vault MK', op_mk)
    p_data('Priv vault MK HMAC', op_mk_hmac)

    overview_key_data = decrypt_opdata(e_ok_d, op_kek_mk, op_kek_hmac)

    h_raw = SHA512.new(overview_key_data).digest()
    op_ok = h_raw[0:32]
    op_ok_hmac = h_raw[32:64]

    p_data('Priv vault OK', op_ok)
    p_data('Priv vault OK HMAC', op_ok_hmac)

    return op_mk, op_mk_hmac, op_ok, op_ok_hmac



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
#
# basic debug / output stuff for consistent output
#
# most reformat the data into "<title>        <data>" format
# and then send to p_debug which decides whether or not to
# actually display the data
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#
# just prints the string, if DEBUG is true
#
def p_debug(out):
    if DEBUG:
        print out

#
# formats title and data into a left-justified 20-char
#   space for the title, then string
def p_str(title, data):
    dat_str = '%s' % data
    lines = dat_str.split('\n')

    p_debug('%-20s %s' % (title, lines[0]))
    for l in lines[1:]:
        p_debug('%20s %s' % ('', l))

#
# takes a hex string and formats an old-school DEBUG-like
#   dump of hex + ascii
#
def dump_line(dat):
    l_raw = binascii.a2b_hex(re.sub(' ', '', dat))
    asc = ''
    for c in l_raw:
        if ord(c) < 31 or ord(c) > 127:
            asc += '.'
        else:
            asc += c

    return('%-40s %s' % (dat, asc))


###############################################################
## TKTK - Need to fix this, drops singleton bytes from last line of hex dump
##   first re.sub seems to be the problem. just iterate and space.
###############################################################
def p_data(title, raw, decoded='', dump=True):
    print ""
    hex = re.sub(r'(....)', r'\1 ', binascii.b2a_hex(raw))
    hex_lines = re.sub(r'((.... ){1,8})', r'\1\n', hex).split('\n')

    if decoded != '' or dump == False:
        p_debug('%-20s %-40s  %s' % (title, hex_lines[0], decoded))
        for l in hex_lines[1:-1]:
            p_debug('%-20s %-40s' % ('', l))

    else:
        d_dat = dump_line(hex_lines[0])
        p_debug('%-20s %s' % (title, d_dat))
        for l in hex_lines[1:-1]:
            d_dat = dump_line(l)
            p_debug('%-20s %s' % ('', d_dat))


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
#
# Convenience functions for input/output
#
# * getbinary - prompt user for binary data (b64 or hex)
# * opb64d, opb64e - base64 decode with 1Password tricks
#    (URL safe altchars, not always including == padding, etc.)
# 
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


#
# The strings stored by 1Password don't always have padding characters at the
#   end. So we try multiple times until we get a good result.
#
# Also, 1Password uses url-safe encoding with - and _ replacing + and /.
#
def opb64d(b64dat):
    try:
        out = base64.b64decode(b64dat, altchars='-_')

    except:
        try:
            out = base64.b64decode(b64dat + '=', altchars='-_')

        except:
            try:
                out = base64.b64decode(b64dat + '==', altchars='-_')
            except:
                print "Problem b64 decoding string: %s" % (b64dat)
                sys.exit(1)

    return out

#
# Simple - encode something in base64 but use URL-safe
#   alt chars - and _ instead of + and /
#
def opb64e(dat):
    return base64.b64encode(dat, altchars='-_')

#
# Collects binary data from the user via a terminal prompt
#
# Because on some systems the raw_input can hang after like
#   1024 characters, we have to wrap it in some crazy termios
#   stuff. 
#
# Then, try to decode it. First assume it's hex, then try
#   base64, both using 1Password tricks, then just plain
#   vanilla base64.
#
# Not exactly bulletproof. (like, abcd1234 is both a hex
#   string and a perfectly acceptable Base-64 encoding.)
#   But for what we're doing (binary encodings of random
#   keys, IVs, and ciphertexts), it's incredibly unlikely
#   that any base-64 string would present as valid hex, 
#   etc.
#
# See also all my previous warnings about using any of 
#   tnis code for something that actually matters. 
#
def get_binary(prompt):
    old_tty_attr = termios.tcgetattr(sys.stdin)
    new_tty_attr = old_tty_attr[:]
    new_tty_attr[3] = new_tty_attr[3] & ~( tty.ICANON)
    termios.tcsetattr(sys.stdin, tty.TCSANOW, new_tty_attr)
    raw_dat = raw_input(prompt)
    termios.tcsetattr(sys.stdin, tty.TCSANOW, old_tty_attr)

    try:
        bin = binascii.a2b_hex(raw_dat)

    except:
        try:
            bin = opb64d(raw_dat)
 
        except:
            try:
                bin = base64.b64decode(raw_dat)

            except:
                print "Unable to decode the input. Enter in hex or base64."
                sys.exit(1)

    return bin

