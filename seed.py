import secrets
import hashlib

def bits_entropy():
    return secrets.token_bytes(16) # esadecimale 

bits_hex=bits_entropy()

sha256=hashlib.sha256() # put inside sha256
sha256.update(bits_hex)
sha256=sha256.hexdigest()

bits=''.join(format(bytes,'08b') for bytes in bits_hex) # bytes hex to bits 


checksum=bin(int(sha256[:1],16))[2:].zfill(4) # first 4 bits of sha256
hex_string=bits + checksum
print(len(hex_string))



# array_bits_words=[hex_bits[i : i + 11] for i in range(0,len(hex_bits) - 11, 11)]
# print(array_bits_words)