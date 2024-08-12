import secrets
import hashlib

def bits_entropy():
    return secrets.token_bytes(16) # esadecimale 

bits_hex=bits_entropy() # range between 128 bits and 512 bits 

sha256=hashlib.sha256() # sha256 for checksum
sha256.update(bits_hex)
sha256=sha256.hexdigest()
checksum=bin(int(sha256[:1],16))[2:].zfill(4) # first 4 bits of sha256

bits=''.join(format(bytes,'08b') for bytes in bits_hex) # bytes hex to bits 

hex_string=bits + checksum
array_bits_words=[hex_string[i : i + 11] for i in range(0,len(hex_string), 11)]

seed_phrase=''
with open('words.txt', mode='r') as f:
    words=f.readlines()
    print(words)

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

# Derive the key
key = hashlib.pbkdf2_hmac(hash_name, seed_phrase, salt, iterations, dklen).hex()
print(key)
