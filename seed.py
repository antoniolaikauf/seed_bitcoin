import secrets
import hashlib
from termcolor import colored
import ecdsa

# def bits_entropy():
#     return secrets.token_bytes(16) # esadecimale 

# bits_hex=bits_entropy() # range between 128 bits and 512 bits 

bits=b'fd3ee153a6081a1811c39590eff75459'
sha256=hashlib.sha256() # sha256 for checksum
sha256.update(bits)
sha256=sha256.hexdigest()
checksum=bin(int(sha256[:1],16))[2:].zfill(4) # first 4 bits of sha256

bits=''.join(format(bytes,'08b') for bytes in bits) # bytes hex to bits 

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

# bits seed
bit_seed= hashlib.pbkdf2_hmac(hash_name, seed_phrase, salt, iterations, dklen).hex()
bit_seed=bytes(bit_seed,'utf-8')

# Derive the key e master chain
private_key_master_chain= hashlib.pbkdf2_hmac(hash_name, bit_seed, b'Bitcoin seed', iterations, dklen).hex()
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
    return (x, y)

pair_key=prefisso(public_key_x, public_key_y)
print(f"chiave pubblica: {public_key}\nchiave pubblica compressa:{pair_key[0]}\npunto x in SECP256k1: {pair_key[0]}\npunto y in SECP256k1: {pair_key[1]},")