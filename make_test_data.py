#
# David Schuetz
# November 2018
#
# https://github.com/dschuetz/1password
#
# Creates a bunch of test data to work with when exploring 1Password
#   encryption. This way you don't have to risk writing your actual password
#   database keys or passwords to bash_history or something like that.
#
# Can preserve certain values to guarantee that subsequent runs produce
#   the same results. Change "PRE_LOAD" to {} to remove all those and
#   (hopefully) produce a completely random set of data. The included
#   pre-loaded data was used in generating my 2018 BSides Delaware talk
#   and associated blog post series (darthnull.org).
#

#
# this is ugly. my apologies. 
#

#
# I considered simply writing full-on sqlite databases that the client can
#   then load, but that would require a lot of extra stuff that really doesn't
#   matter to this experiment (just playing with encryption and vaults), and
#   the client wouldn't be guaranteed to work anyway (since it wouldn't have a
#   valid cloud-based account to connect back to).
#


# 
# Optional Pre-Load Data
#
# Can pre-set different items to ensure that multiple runs produce the same
# results.
#
# Will be processed in turn by each individual generation routine.
#


PRE_LOAD = {
    'muk_salt': 'cA4f6QY7wwUoclj74RMvUg==',
    'srp_salt': 'OtQiDn4YnrTMoYXponFtfA==',
    'vault1': {
        'uuid': "r07y2eh9nj8vjf20g6a9vpbkv7",
        'k': "N5UH1HxXJgtTSrvMHWStrEnuiHiq9Q1Vf064XlCYfgg=",
        'iv': 'py0VvhU4S0lsVp3HCWPVBQ==',
        'vault_uuid': 'ixaw6slq5k7c7d71lwzkh87qy1',
    }, 
    'keyset1': {
            'uuid': 'qn8uimc4l7sofa26yivex24j7q',
            'pub': {
                'e': 'AQAB',
                'n': 'xA6dAIu2_S9Ia_xRkodmvBv9w4pMyjE7FFAiXKTcQJS8d1RLkY82hwghBa6YK7V28_-S0Hfe2_NecesRMCpDf03kl1SClJkl8bJpJ0AwZFhvj6JO1JUZAj8o06OpgUCij_Jt8YSiu8bQIXgH5bEEkZ3oBx1OyozgqCo6JBa7cQVlv2LGV25YnqIbzOTof8YBZMNM0GuzPQQDxJUEB4ktmKekFjtDvHzAUmtMEgGYpbgXl4AmRAbHlYPpepSBplqXSrJfxVfEgftAJudjQsrMr_uVNX5TYGgFJDqUzkiXBXEUFy22GqcIArLLiOtvUwEU843wYpLtSPN-A20YLfSTCw',
                'kty': 'RSA'
            }, 
            'priv': {
                'iv': 'x_pZCisivs-aCINbqS4fLQ==',
                'key': {
                    'e': 'AQAB', 
                    'd': 'XcdvqfcqjGi1h5GloyVJKulotMPOf1iVHd5G0XG6ONnsXFfh3bpXJrfos8MT3rRqNcQmAbmUzDjZEDyUeCl_J8GmegxeeZ3X3Iiua6v0ecsjcdz9QAohcEWtza4XQlAcciZQGJqNDKzImXnErUXDHbQebGjEa3Z_b3DjZqfI-QH5DYDMh5W61L7Ky8_8kc54A9EtJupqtKZwYnBtazzLTcl82APkyQ71aN9kD-iO8qA3lAQGkUykRBa_8TF0tDCGgFfW7ijcGk06NGsYex9ir_n8fYZOP3LXahEMO5_3j4vIixmktFpI8IhtdQNvXqYir3JyB3WOmszr5XC4VasAYQ', 
                    'n': 'xA6dAIu2_S9Ia_xRkodmvBv9w4pMyjE7FFAiXKTcQJS8d1RLkY82hwghBa6YK7V28_-S0Hfe2_NecesRMCpDf03kl1SClJkl8bJpJ0AwZFhvj6JO1JUZAj8o06OpgUCij_Jt8YSiu8bQIXgH5bEEkZ3oBx1OyozgqCo6JBa7cQVlv2LGV25YnqIbzOTof8YBZMNM0GuzPQQDxJUEB4ktmKekFjtDvHzAUmtMEgGYpbgXl4AmRAbHlYPpepSBplqXSrJfxVfEgftAJudjQsrMr_uVNX5TYGgFJDqUzkiXBXEUFy22GqcIArLLiOtvUwEU843wYpLtSPN-A20YLfSTCw', 
                    'q': '8Kuuf2mnoNK1skNuxJU38Q6HC6cq9JoHN1U5dYKIcAXd0B1wEqHGcbo8UyviftfdPRy2fomKu1-c0uWcOzBZmlV4SkQ-_TwxcFPgTVcrhuAESHERZIYJuIr6JENoD7iph_BGOF-ftVGBULT7fFRH47t0jPkfTolXeC2tLIsQbuU', 
                    'p': '0It5RDblXwYnJg-xuBrww6bxNr11x8ILCEVojwuAaNFegAqwPHbUw4nekx5mML30HltVgg3i3bi0ITLdHVqvdy9zUetTsEhsYlk9Zq8ox6nGQ9qEa-Hnu4YCB5Uh5iHMBZyUlmjRUPh1V7NcyafzjgJSin8-Me_DKrHxdalU6y8',
                    'kty': 'RSA'
                }
            }, 'sym': {
                'k': 'Sco1rWpdmrLiAeZNtwAlCQsMMqN46AnyGasaMu3EqlQ=',
                'iv': '2FF8mtGD55z84h9jMtWAyQ==',
            },
        },
    'keyset2': {
            'uuid': 's08414l8481og4hk36hw8jshn0',
            'pub': {
                'e': 'AQAB',
                'n': 'rZKS0l3iC9OQNVcrXuE-dFD-ML_E4ypbbysOKv0_bQy1s8yZuH3obiMU2hCtkJwC7Dn3oaMFwmxRoX6xY8HgtpUPIYwiqpuEKLEpMZ7HkbE7ktZK45A2hDXe3MwFgg50u1vnd2DKZh_glKM2mkH9XKkdTFwN_YB-qfh3n4Zgmdm6i6IoyRFRpnf9stI-hrc8aTWeHFu4xIiIQw1GI6qcvpRpb5cepmL7j8C58I4RofcZv2FjV-COoCZ0FAztythDtAg0o7W8sBCJGKG2wURmlPUy_2Mz_5Y7pC1bVbGxyOgYgSN6SjiyXtw0tI5SmTeLkpjnO0KndWFL_e3bf0rO9w',
                'kty': 'RSA'
            }, 
            'priv': {
                'iv': '1FSnF9hqWPZDhMoKHP8NRw==',
                'key': {
                         "e": "AQAB", 
                         "d": "J_7t6R6sD1iVUs0-17Kkfw4IvLf7yPLCNfggYCSSAHFcz00WoO4WaIaZ7_PG4tsoS0HCP5M-qQHnv4RfoOKUgs4POgY-GL0UM4I7QU1apEZIOXo6sHxTK5z0OUGkBUeKe3_ecuIxUV4IFIgVdW8-UCNB9o4BxUfeKBFykyZWTSz-fLbIoToAmxPCqmlFYIWBZ3uPmbr9vyv1JCZF6GzIeH7LeuJz_EgZsuKSSrumLsWGS7tZYE5XipfmrdVdpTgElqWVY0Xh-_c4ooLwCtBqEW7XjJXrCIo73yGjFMLSRqeinWaEEE4RXWtu2Ut6ntvXqMLQOWaelQ_MbOLPRbT1CQ", 
                         "n": "rZKS0l3iC9OQNVcrXuE-dFD-ML_E4ypbbysOKv0_bQy1s8yZuH3obiMU2hCtkJwC7Dn3oaMFwmxRoX6xY8HgtpUPIYwiqpuEKLEpMZ7HkbE7ktZK45A2hDXe3MwFgg50u1vnd2DKZh_glKM2mkH9XKkdTFwN_YB-qfh3n4Zgmdm6i6IoyRFRpnf9stI-hrc8aTWeHFu4xIiIQw1GI6qcvpRpb5cepmL7j8C58I4RofcZv2FjV-COoCZ0FAztythDtAg0o7W8sBCJGKG2wURmlPUy_2Mz_5Y7pC1bVbGxyOgYgSN6SjiyXtw0tI5SmTeLkpjnO0KndWFL_e3bf0rO9w", 
                         "q": "6pifes0RIJfKh_jf_JsE_ndeFR6CJcHE9AKTVNL8Xpvb8XpagJx1wwKXZOqOstP9UqcGq7O11oHjo2DFiy_5dBUwl4hzJ4aCewrAFeFQfZduU9YUj1NLm0FaOlBKrFnyz-ldmmC_391LQpEhcIbd3OkuuIuaqOrcYJzUVbDWLOk", 
                         "p": "vWik3JXLjwMgiLwtM_sxPSPB79nkq3G8jBZyBmzrWzZFKWqfK3Td2rJ315UOXaLhW3Z6R7JGkujlr15oecs27jl1SITF4TPxZnATCLOH6UOf7VFFoZr8zTNo8mEoE_Yvd3KNfjiM9VWJctNHhbyzgH3KFHDeazm6a4hw8yEeMN8", 
                        'kty': 'RSA'
                }
            }, 'sym': {
                'k': 'E8nTamfBwcgmCR3cq5Z5b5ssaRvj2xMVc_10NdTZhkE=',
            },
        },
    'mac_enc_login_iv': 'eaPYeKzI6X8xvRBonJ7Y2g==',
    'win_mk': 'cgUlD73bdmMYKUtpv3CwHgnbI8/fTBumvhi5EKoRdbU=',
    'win_mk_hmac': 'rRTU/gk49J/ygyjJP5yCGmVEB1O3iMxjaLE7V66FQms=',
    'win_emk_iv': '6SxXzysYhFber930SflusA==',
    'win_emk_padding': 'RpUVKSWc32nU7wrwhrlwDg==',
    'win_enc_login_padding': 'McpQvMgog4rwvRTH',
    'emk_iter': 588972,
    'emk_salt': 'wcU1SabU3OEoVfmrmYqwTA==',
    'win_enc_login_iv': '50C0aQfo36gxlOcoF75Npw==',
    'local_vault': {
        'salt': 'AXJZTNToCfbWGM61D5fg3w==',
        'mk': {
            'data': 'HdZBvq7CH6cUau1qtDhgqQqJRWeOfcB6olMi6FHMyojFDjUKVxj3bSgSwxjb3UA1I9PdXUw3HI3StQPvGXvrQUAh5FgAZ61fMTq+QeJ2EDKbCQ+96y3NR6bsLo7crRV5XtOSp9Zr/WhzPA1gJz60O6dhpJ8/NmYQe6O5YgLAdVGjrSbHf6g9mic/Pe7P5qYZIJrdlJ1Hjce45WUN6St7stRDggDeCX438b/IUrzfsTEBRVl++gWdQ4itif7GmdwMdHVpPDdLx6urNSKFQBbQXQxXQ7gH1NwgqsXTHidDeKeg6qaN99ayiuBiuOqcY0X1yemHzuMAuN1rxaubVWB0LA==',
            'iv': 'mtn1wHVe5VbdZCfIhPU+lQ==',
            'padding': '+i8dDdQkQGbkUIv3RlhVxQ==',
        }, 
        'ok': {
            'data': '9azgZJxBKAeQdxdU3gjU6cM7LP2Kx/Ch9Pwfq41RxreyJwXv820oB5ljFlM1EvvY2SSfwd+B/Jgi07aTSpOw7Q==',
            'iv': 'nNugIZecvwuWrncmby4V7w==',
            'padding': 'TDFPhZ35Y4DYUxcsoZ0IuA==',
        },
        'enc_login': {
            'iv': 'w+NRRE4uIpM3gLRsFhcvUw==',
            'padding': 'NYoQ6QLE9g==',
        }
    },
    'local_vault_data': {
        'ik_iv': 'TLJVIK30PFzpdsuC+gfFTw==',
        'ik_key': 'zWDXNOvfF9XZ50Jk773Q/8yDO/NwgCLoEvNLhqyJWfc=',
        'ik_hmac': 'JfjcxD/BNf93c5BaUtN0ZCsiGm8dkIZaIKe6PJ8XTJw=',
        'ik_padding': '+DlGQVEt295jIynBBdkOpw=='
    }
}






DEBUG=1

SecretKey ='A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB'
MasterPassword ='update-clown-squid-bedpost'
Email='nobody@example.com'


p2c_muk = 100000
alg_muk = 'PBES2g-HS256'
p2s_muk = ''

p2c_srp = 100000
alg_srp = 'SRPg-4096'
p2s_srp = ''

sym_keys = {}
pri_keys = {}
pub_keys = {}

keysets = {}

vault_access = {}
vaults = {}
vault_kids = {}

items = {}

emk_iter = 588972
emk_slen = 16

opk_iter = 100000

from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256, SHA512

from jwkest.jwk import RSAKey, load_jwks
from jwkest.jwe import JWE
from Crypto.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP



import hashlib,hmac

import sys, base64, binascii, re, json, struct


import optestlib


def read_default(tag, decode=True):
    cur_dict = PRE_LOAD
    tags = tag.split('.')
    for t in tags[0:-1]:
        cur_dict = cur_dict.get(t)
        if cur_dict == None:
            break
    
    if cur_dict == None:
        return None
        
    t = cur_dict.get(tags[-1])

    if t == None:
        return None
    
    if decode:
        return(optestlib.opb64d(t))
    else:
        return t
 

def main():
    global p2s_muk, p2s_srp


    optestlib.p_debug(" *** Generating Test Data ***")

    optestlib.p_debug("\n\n**************************************************************")
    optestlib.p_debug('* Deriving Master Unlock Key (MUK) (AES kid mp)')

    p2s_muk = read_default('muk_salt') or get_random_bytes(16)
    MUK = optestlib.compute_2skd(SecretKey, MasterPassword, Email, 
        p2s_muk, p2c_muk, alg_muk)
    sym_keys['mp'] = MUK


    optestlib.p_debug("\n\n**************************************************************")
    optestlib.p_debug('* Deriving SRP-X') 

    p2s_srp = read_default('srp_salt') or get_random_bytes(16)
    SRPx = optestlib.compute_2skd(SecretKey, MasterPassword, Email, 
        p2s_srp, p2c_srp, alg_srp)
    sym_keys['srp-x'] = SRPx

    optestlib.p_debug("\n\n**************************************************************")
    optestlib.p_debug('* Generating keyset1')
    keyset1_kid = gen_keyset('keyset1', 'mp')

    optestlib.p_debug("\n\n**************************************************************")
    optestlib.p_debug('* Generating keyset2')
    keyset2_kid = gen_keyset('keyset2', keyset1_kid)



    optestlib.p_debug("\n\n**************************************************************")
    optestlib.p_debug('* Generating login detail records')
    mac_login_data = gen_mac_login()
    mac_login = enc_mac_login(keyset1_kid, mac_login_data)

    optestlib.p_debug('\n* Generating Windows EMK')
    emk = gen_emk()

    optestlib.p_debug('\n* Generating Windows login details')
    win_login = enc_win_login()

    optestlib.p_debug('\n* Generating private vault unlock keys')
    op_local_vault_keys = gen_local_vault_keys()
    op_local_vault_login = gen_local_login(mac_login_data)


    optestlib.p_debug("\n\n**************************************************************")
    optestlib.p_debug('* Generating vaults')

    vault1_kid = gen_vault_key('vault1', keyset1_kid)
    gen_vault_entry('vault1', vault1_kid)

    optestlib.p_debug("\n\n**************************************************************")
    optestlib.p_debug('* Generating vault items')

    uuid = read_default('items.1.uuid')
    gen_item('items.1', 'vault1', uuid, title='My test!', url='https://example.com', user='user', password='password')


    optestlib.p_debug('** Local private vault item')
    old_vault_data = gen_old_vault_data()
    


    print "\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n"
    print " *** Generated Data ***\n"

    print("MUK data:")
    print("  Password:      %s" % MasterPassword)
    print("  Secret Key:    %s" % SecretKey)
    print("  Email:         %s" % Email)
    print("  p2s:           %s" % optestlib.opb64e(p2s_muk))
    print("  p2c:           %d" % p2c_muk)
    print("  alg:           %s" % alg_muk)
    print("  MUK:           %s" % optestlib.opb64e(MUK))

    print("\nSRP data")
    print("  p2s:           %s" % optestlib.opb64e(p2s_srp))
    print("  p2c:           %d" % p2c_srp)
    print("  alg:           %s" % alg_srp)
    print("  SRP-X:         %s" % optestlib.opb64e(SRPx))


    print("\n\nMaster key (mk): %s" % optestlib.opb64e(sym_keys['mk']))

    print("\n\nSymmetric Keys (kid, base64-encoded key):")
    for k in sorted(sym_keys):
        print("  %-26s  %s" % (k, optestlib.opb64e(sym_keys[k])))

    print("\n\nPublic Keys (kid, json dump of key):")
    for k in sorted(pub_keys):
        print("  %-26s  %s\n" % (k, json.dumps(pub_keys[k], indent=4)))

    print("\n\nPrivate Keys (kid, json dump of key):")
    for k in sorted(pri_keys):
        print("  %-26s  %s\n" % (k, json.dumps(pri_keys[k], indent=4)))

    print("\nKeyset 1:\n%s" % json.dumps(keysets[keyset1_kid], indent=4))
    print("\nKeyset 2:\n%s" % json.dumps(keysets[keyset2_kid], indent=4))

    print("\nmacOS enc_login:\n%s" % json.dumps(mac_login, indent=4))

    print("\nEMK:\n%s" % emk)

    print("\nWindows enc_login:\n%s" % win_login)

    print("\nLocal vault key data:\n%s" % json.dumps(op_local_vault_keys, indent=4))

    print("\nAccount enc_login encrypted for local vaults:\n%s" % json.dumps(op_local_vault_login, indent=4))

    for vault in ['vault1']:
        print("\nVault Data for %s:\n" % vault)
        print("  * Vault access key\n%s" % (json.dumps(vault_access[vault])))
        print("  * Vault attributes\n%s" % (json.dumps(vaults[vault])))

    print("\nEncrypted vault items")
    for item in items:
        print json.dumps(items[item]), "\n"


    print("\nLocal private vault item")
    print json.dumps(old_vault_data)

#
# generate encrypted vault items
#
def gen_item(name, vault, uuid, title=None, url=None, user=None, password=None):
    global items
    ekid = vault_kids[vault]

    overview = {'ainfo': 'account-name', 'title': title, 'url': url}

    iv = read_default(name + 'ov_iv')
    iv, enc_overview = optestlib.enc_aes_gcm(json.dumps(overview), sym_keys[ekid], iv)

    ov_dat = {'data': optestlib.opb64e(enc_overview), 'iv': optestlib.opb64e(iv), 'kid': ekid, 
        'cty': 'b5+jwk+json', 'enc': 'A256GCM'}

    details = {'fields': [ {'name': 'username', 'type': 'T', 'value': user},
        {'name': 'password', 'type': 'P', 'value': password} ] }

    iv = read_default(name + 'det_iv')
    iv, enc_details = optestlib.enc_aes_gcm(json.dumps(details), sym_keys[ekid], iv)

    det_dat = {'data': optestlib.opb64e(enc_details), 'iv': optestlib.opb64e(iv), 'kid': ekid, 
        'cty': 'b5+jwk+json', 'enc': 'A256GCM'}

    out = {'vault': vault, 'item_num': name, 'overview': ov_dat, 'details': det_dat}

    items[name] = out

#
# generate vault table entry for given vault name and kid
#
def gen_vault_entry(name, ekid):
    global vaults

    out = {'enc': 'A256GCM', 'kid': ekid, 'cty': 'b5+jwk+json'}
    uuid = read_default(name + '.vault_uuid', decode=False) or gen_uuid()
    
    attrs = {'uuid': uuid, 'name': 'Test vault: %s' % name, 'type': 'P', 'desc': 'unk-b64-blob', 'avatar': ''}

    iv = read_default(name + '.iv')
    iv, enc_attrs = optestlib.enc_aes_gcm(json.dumps(attrs), sym_keys[ekid], iv=iv)
    out['data'] = optestlib.opb64e(enc_attrs)
    out['iv'] = optestlib.opb64e(iv)
    
    vaults[name] = out


#
# generate a vault entry for local vaults (old style)
#
def gen_old_vault_data():
    out = {}

    m_key = sym_keys['opv-mk']
    m_hmac = sym_keys['opv-mk-hmac']
    o_key = sym_keys['opv-ok']
    o_hmac = sym_keys['opv-ok-hmac']

    
    o_data = '{"title":"Vault entry for local private vaults","url":"www.example.com","ainfo":"-","ps":75}'
    o_data_enc = optestlib.encrypt_opdata(o_data, o_key, o_hmac)

    out['overview_data'] = optestlib.opb64e(o_data_enc)

    ik_iv = read_default('priv_vault_data.ik_iv') or get_random_bytes(16)
    ik_key = read_default('priv_vault_data.ik_key') or get_random_bytes(32)
    ik_hmac = read_default('priv_vault_data.ik_hmac') or get_random_bytes(32)
    ik_padding = read_default('priv_vault_data.ik_padding')
    
    optestlib.p_data('Item key IV', ik_iv)
    optestlib.p_data('Item key', ik_key)
    optestlib.p_data('Item HMAC key', ik_hmac)

    item_key_data = optestlib.encrypt_tag_cbc(ik_key + ik_hmac, ik_iv, m_key, m_hmac)
    check = optestlib.decrypt_verify_cbc(item_key_data, m_key, m_hmac)

    out['key_data'] = optestlib.opb64e(item_key_data)

    item_data = '{"fields": [ { "id": "OldPassword;opid=__2", "name": "OldPassword", "type": "P", "value": "notagoodpassword" }, { "designation": "password", "id": "NewPassword;opid=__3", "name": "NewPassword", "type": "P", "value": "OldSk00lRulzFTW!" } ] }'

    item_data_enc = optestlib.encrypt_opdata(item_data, ik_key, ik_hmac, iv=ik_iv, padding=ik_padding)

    out['data'] = optestlib.opb64e(item_data_enc)

    return out
    
    

#
# generate a vault key and store in vault access 
#
def gen_vault_key(name, ekid):
    global vault_access, vault_kids

    optestlib.p_debug('** Generating access keys for %s' % name)
    out= {"enc":"RSA-OAEP","kid":ekid,"cty":"b5+jwk+json"}

    new_kid = read_default(name + '.uuid', decode=False)
    new_key = read_default(name + '.k')

    kid, sym_key = gen_sym_key(ekid, new_kid=new_kid, k=new_key)

    out['data'] = sym_key
    vault_access[name] = sym_key
    vault_kids[name] = kid
    
    return kid

def gen_local_vault_keys():
    global sym_keys

    optestlib.p_debug('\n** Generating MasterKey (MK) and OverviewKey (OK) (OnePassword local private vaults)')

    salt = read_default('local_vault.salt') or get_random_bytes(16)

    mkd = read_default('local_vault.mk.data') or get_random_bytes(256)
    mk_iv = read_default('local_vault.mk.iv')
    mk_padding = read_default('local_vault.mk.padding')

    okd = read_default('local_vault.ok.data') or get_random_bytes(64)
    ok_iv = read_default('local_vault.ok.iv')
    ok_padding = read_default('local_vault.ok.padding')

    data = optestlib.gen_local_vault_keys(MasterPassword, salt,
        mkd, mk_iv, mk_padding, okd, ok_iv, ok_padding)

    sym_keys['opv-mk'] = data['master_key']
    sym_keys['opv-mk-hmac'] = data['master_key_hmac']
    sym_keys['opv-ok'] = data['overview_key']
    sym_keys['opv-ok-hmac'] = data['overview_key_hmac']

    enc_master_key = data['enc_master_key_data']
    enc_overview_key = data['enc_overview_key_data']

    profile_data = {'salt': optestlib.opb64e(salt), 'iterations': opk_iter, 
        'overview_key_data': optestlib.opb64e(enc_overview_key),
        'master_key_data': optestlib.opb64e(enc_master_key)}

    
    return profile_data


def gen_local_login(mac_login):
    iv = read_default('local_vault.enc_login.iv')
    padding = read_default('local_vault.enc_login.padding')

    op_mk = sym_keys['opv-mk'] 
    op_mk_hmac = sym_keys['opv-mk-hmac'] 

    enc_login = optestlib.encrypt_opdata(json.dumps(mac_login), op_mk, op_mk_hmac,
        iv=iv, padding=padding)

    account_data = {'enc_login': optestlib.opb64e(enc_login)}

    return account_data

#
# generate windows EMK block 
#
def gen_emk():
    global sym_keys
    optestlib.p_debug('\n** Generating Encrypted Master Key (EMK) block')

    win_mk = read_default('win_mk') or get_random_bytes(32)
    sym_keys['win-mk'] = win_mk

    win_mk_hmac = read_default('win_mk_hmac') or get_random_bytes(32)
    sym_keys['win-mk-hmac'] = win_mk_hmac

    optestlib.p_data('New MK', win_mk)
    optestlib.p_data('New MK HMAC Key', win_mk_hmac)

    emk_salt = read_default('emk_salt') or get_random_bytes(emk_slen)
    
    raw_derived_key = hashlib.pbkdf2_hmac('sha512', MasterPassword, emk_salt, emk_iter, 64)
    enc_key = raw_derived_key[0:32]
    enc_hmac_key = raw_derived_key[32:64]

    optestlib.p_data('MP-derived key', enc_key)
    optestlib.p_data('MP-derived HMAC key', enc_hmac_key)

    iv = read_default('win_emk_iv')
    padding = read_default('win_emk_padding')
    op_msg = optestlib.encrypt_opdata(win_mk + win_mk_hmac, enc_key, enc_hmac_key, 
        iv=iv, padding=padding)

    emk = struct.pack('<I', emk_iter)   # iterations
    emk += struct.pack('<I', emk_slen)  # salt length
    emk += emk_salt
    emk += struct.pack('<I', len(op_msg)) 
    emk += op_msg 

    optestlib.p_data('Final EMK block', emk)

    return optestlib.opb64e(emk)


#
# encrypt windows login data
#
def enc_win_login():
    optestlib.p_debug('\n** Windows login details for accounts table')
    
    data = json.dumps({'accountKey': SecretKey, 'password': MasterPassword})

    iv = read_default('win_enc_login_iv')
    padding = read_default('win_enc_login_padding')

    op_msg = optestlib.encrypt_opdata(data, 
        sym_keys['win-mk'], sym_keys['win-mk-hmac'], iv=iv, padding=padding)

    return optestlib.opb64e(op_msg)

# 
#

#
# generate account login data structure for macOS client
#
def gen_mac_login():
    optestlib.p_debug('\n** Mac login details for accounts table')
    enc_login = {'email': Email, 'personalKey': SecretKey}

    muk = {'k': optestlib.opb64e(sym_keys['mp']), 'key_ops': ['encrypt','decrypt'], 
        'alg':'A256GCM', 'ext':True, 'key':'oct', 'kid':'mp'}

    srp = {'hexX': optestlib.opb64e(sym_keys['srp-x']), 
        'params': {'method': alg_srp, 'iterations': p2c_srp, 'alg': alg_muk,
        'salt': optestlib.opb64e(p2s_srp)}}

    enc_login['masterUnlockKey'] = muk
    enc_login['SRPComputedXDictionary'] = srp

    optestlib.p_str("mac enc_login contents:", json.dumps(enc_login, indent=4))

    return enc_login


#
# encrypt account login data for macOS client
#
def enc_mac_login(kid, mac_login_data):
    out_pt = json.dumps(mac_login_data) 

    iv = read_default('mac_enc_login_iv')
    iv, ct = optestlib.enc_aes_gcm(out_pt, sym_keys[kid], iv=iv)

    out = {'iv': optestlib.opb64e(iv), 'data': optestlib.opb64e(ct), 'enc': 'A256GCM', 
        'cty': 'b5+jwk+json', 'kid': kid}
    
    optestlib.p_str('Encrypted macOS enc_login:', out)

    return out
    

#
# generate a keyset
#   * enc_sym_key
#   * enc_pri_key
#   * pub_key
#
# Encrypt the keyset (the sym key) with the key identified by ekid
# If ekid = 'mp' then it's the primary keyset, and add the global 2SKD params
#
def gen_keyset(name, ekid):
    optestlib.p_debug('** Generating %s - encrypted by %s' % (name, ekid))
    out = {'encrypted_by': ekid}

    iv = None
    try:
        if ekid == 'mp':
            iv = read_default(name + '.sym.iv') 

        new_kid = read_default(name + '.uuid', decode=False)
        new_key = read_default(name + '.sym.k')

        kid, sym_key = gen_sym_key(ekid, new_kid=new_kid,
            iv=iv, k=new_key)

        new_pub = read_default(name + '.pub', decode=False)
        new_priv = read_default(name + '.priv', decode=False)
        rsa_pub, rsa_priv = gen_rsa_key(kid, pub=new_pub, priv=new_priv)
        

    except:
        kid, sym_key = gen_sym_key(ekid)
        rsa_pub, rsa_priv = gen_rsa_key(kid)


    if ekid == 'mp':
        sym_keys['mk'] = sym_keys[kid]
        sym_key['p2s'] = optestlib.opb64e(p2s_muk)
        sym_key['p2c'] = p2c_muk
        sym_key['alg'] = alg_muk

    out['uuid'] = kid 
    out['enc_sym_key'] = sym_key

    out['enc_pri_key'] = rsa_priv
    out['pub_key'] = rsa_pub

    keysets[kid] = out

    return kid


def gen_rsa_key(ekid, pub=None, priv=None):

    if priv == None:
        new_priv = RSA.generate(2048)
        jwk_priv = RSAKey(key=new_priv).to_dict()
        iv = None
    else:
        iv = optestlib.opb64d(priv['iv'])
        jwk_priv = priv['key']

    if pub == None:
        new_pub = new_priv.publickey()
        jwk_pub = RSAKey(key=new_pub).to_dict()
    else:
        jwk_pub = pub


    jwk_priv['alg'] = 'RSA-OAEP'
    jwk_priv['key_ops'] = ['decrypt']
    jwk_priv['kid'] = ekid

    jwk_pub['key_ops'] = ['encrypt']
    jwk_pub['alg'] = 'RSA-OAEP'
    jwk_pub['ext'] = True
    jwk_pub['kid'] = ekid

    optestlib.p_str("New Private key", json.dumps(jwk_priv, indent=4))

    pri_keys[ekid] = jwk_priv
    pub_keys[ekid] = jwk_pub

    key_dat_str = json.dumps(jwk_priv)

    
    optestlib.p_debug('\n*** Encrypting pri key with AES kid %s' % ekid)

    iv, ct = optestlib.enc_aes_gcm(key_dat_str, sym_keys[ekid], iv=iv)

    optestlib.p_data('IV', iv, dump=False)
    optestlib.p_data('KEY', sym_keys[ekid], dump=False)
    optestlib.p_data('Ciphertext', ct, dump=False)

    priv_out = {'kid': ekid, 'cty': 'b5+jwk+json', 'enc': 'A256GCM',
        'data': optestlib.opb64e(ct), 'iv': optestlib.opb64e(iv)}

    optestlib.p_str("New Public key", json.dumps(jwk_pub, indent=4))

    return jwk_pub, priv_out



def gen_sym_key(ekid, new_kid=None, iv=None, k=None):
    out = {'kid': ekid, 'cty': 'b5+jwk+json'}

    if new_kid != None:
        kid = new_kid
    else:
        kid = gen_uuid()

    if k != None:
        new_key = k
    else:
        new_key = get_random_bytes(32)

    key_dat = {'alg': 'A256GCM', 'ext': True, 'key_ops': ['decrypt', 'encrypt'], 'kty': 'oct', 'kid': kid}

    key_dat['k'] = optestlib.opb64e(new_key)

    key_dat_str = json.dumps(key_dat)
    optestlib.p_str("New symmetric key",json.dumps(key_dat, indent=4))

    sym_keys[kid] = new_key
    if ekid == 'mp':
#        sym_keys['mk'] = new_key

        optestlib.p_debug('\n*** Encrypting sym key with AES kid %s' % ekid)
        iv, ct = optestlib.enc_aes_gcm(key_dat_str, sym_keys[ekid], iv=iv)

        optestlib.p_data('IV', iv, dump=False)
        optestlib.p_data('KEY', sym_keys[ekid], dump=False)
        optestlib.p_data('Ciphertext', ct, dump=False)

        out['iv'] = optestlib.opb64e(iv)
        out['data'] = optestlib.opb64e(ct)
        out['enc'] = 'A256GCM'

    else:  # only the primary sym_key is itself AES encrypted, rest by RSA
        optestlib.p_debug('\n*** Encrypting sym key with RSA kid %s\n' % ekid)

        jwkj = '{"keys": [%s]}' % json.dumps(pub_keys[ekid])
        jwk = load_jwks(jwkj)[0]
        optestlib.p_str('Public key e:', jwk.e)
        optestlib.p_str('Public key n:', jwk.n)
        RSA_Key = RSA.construct((jwk.n, jwk.e))

        C = PKCS1_OAEP.new(RSA_Key)
        ct = C.encrypt(key_dat_str)

        out['enc'] = 'RSA-OAEP'
        out['data'] = optestlib.opb64e(ct)
        optestlib.p_debug('')
        optestlib.p_data('RSA-OAEP ciphertext', ct, dump=False)

    return kid, out


def gen_uuid():
    out = ''
    for rc in get_random_bytes(26):
        c = ord(rc) % 36
        if c < 10:
            ch = chr(48+c)
        else:
            ch = chr(97+c-10)

        out += ch 
    return out



if __name__ == '__main__':
    main()

