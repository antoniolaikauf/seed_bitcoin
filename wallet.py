import hashlib
import ecdsa
import base58
import pdb
from Crypto.Hash import RIPEMD160
from termcolor import colored


entropy_bits= 'fd3ee153a6081a1811c39590eff75459'
bits=''.join([bin(int(x,16))[2:].zfill(4) for x in entropy_bits])

sha256=hashlib.sha256() # sha256 for checksum
sha256.update(bytes(entropy_bits,'utf-8'))
sha256=sha256.hexdigest()
checksum=bin(int(sha256[:1],16))[2:].zfill(4) # first 4 bits of sha256

hex_string=bits + checksum
array_bits_words=[hex_string[i : i + 11] for i in range(0,len(hex_string), 11)]
seed_phrase=''
with open('words.txt', mode='r') as f:
    words=f.readlines()

    for x in range(12): # seed prhase 12
        extracted_bits= array_bits_words[x]

        index_word=int(extracted_bits,2)

        seed_phrase+= ' ' +  words[index_word].rstrip()
    seed_phrase=bytes(seed_phrase,'utf-8')
    print(seed_phrase)

# Parameters
hash_name = 'sha512'  # The hash algorithm to use
# passphrase= b'c'
salt = b'mnemonic' # + passphrase  # mnemonic è una stringa che è sempre permanente 
iterations = 2048  # Number of iterations
dklen = 64  # Length of the derived key (512 bits)

def key_stretching_function(n,s_p,s,i,dk): # bits seed
    bit_seed= hashlib.pbkdf2_hmac(n, s_p, s, i, dk).hex()
    return bytes(bit_seed,'utf-8')

bits_seed_512=key_stretching_function(hash_name,seed_phrase,salt,iterations,dklen)

# Derive the key e master chain
private_key_master_chain= hashlib.pbkdf2_hmac(hash_name, bits_seed_512, b'Bitcoin seed', iterations, dklen).hex()
# print(private_key_master_chain)

private_key=private_key_master_chain[:64]
master_chain=private_key_master_chain[64:]
print(f"private key: {colored(private_key, 'red')}, master chain: {colored(master_chain, 'blue')}")

private_key_bytes = bytes.fromhex(private_key)
sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
vk = sk.verifying_key
public_key = (b'\04' + vk.to_string()).hex() # 04 | x | y cordinate sulla curva SECP256k1
public_key_y, public_key_x = hex(vk.pubkey.point.y())[2:], hex(vk.pubkey.point.x())[2:] # cordinate 

def prefisso(x, y, p=''): # prefisso
    if int(y[-1], 16) % 2 == 0:  p='02'
    else: y = p='03'
    y,x = p + y, p + x
    return {'public_key_x':x, 'public_key_y':y}

'''
la chiave pubblica compressa è di 264 bits perchè si aggiunge il prefisso ed è sempre la cordinata x della curva ellittica 
'''

pair_key=prefisso(public_key_x, public_key_y)
print(f"chiave pubblica: {public_key}\nchiave pubblica compressa:{pair_key['public_key_x']}\npunto x in SECP256k1: {pair_key['public_key_x']}\npunto y in SECP256k1: {pair_key['public_key_y']},")

class Bitcoin_address():
    def __init__(self, public_key):
        self.publick_key=public_key

    def sha_256(self): # primo processo per address del double hash #32 bytes
        sha256_kp=hashlib.sha256()
        sha256_kp.update(bytes(self.publick_key,'utf-8'))
        sha256_kp=sha256_kp.hexdigest()
        return sha256_kp
    
    def ripend_160(self,value): #secondo processo del double hash #20 bytes
        h=RIPEMD160.new()
        h.update(bytes(value,'utf-8'))
        h=h.hexdigest()
        return h # payload 
    
    def base58encoding(self,payload):# chiave pubblica
        version = '00'
        data = version + payload
        #two sha256
        first_sha256,second_sha256= hashlib.sha256(), hashlib.sha256()
        first_sha256.update(bytes(data, 'utf-8'))
        second_sha256.update(bytes(first_sha256.hexdigest(),'utf-8'))
        second_sha256=second_sha256.hexdigest()

        checksum = second_sha256[:8] # checksum
        data+= checksum # 50 bytes
        address=base58.b58encode_check(bytes.fromhex(data))
        return address

address=Bitcoin_address(pair_key['public_key_x'])
payload=address.ripend_160(address.sha_256())
print(len(address.base58encoding(payload)))

print(len('1CBUDhWJyJHjLPqfwt4abJrTuwFSa933JV'))