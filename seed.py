import secrets
import hashlib

def bits_entropy():
    return secrets.token_bytes(16) # esadecimale 

bits_hex=bits_entropy()

sha256=hashlib.sha256() # sha256 for checksum
sha256.update(bits_hex)
sha256=sha256.hexdigest()
checksum=bin(int(sha256[:1],16))[2:].zfill(4) # first 4 bits of sha256

bits=''.join(format(bytes,'08b') for bytes in bits_hex) # bytes hex to bits 

hex_string=bits + checksum
array_bits_words=[hex_string[i : i + 11] for i in range(0,len(hex_string), 11)]

with open('words.txt', mode='r') as f:
    words=f.readlines()
    seed_phrase=''

    for x in range(12): # seed prhase 12
        extracted_bits= array_bits_words[x]

        index_word=int(extracted_bits,2)

        seed_phrase+= ' ' +  words[index_word]
    
    print(seed_phrase)