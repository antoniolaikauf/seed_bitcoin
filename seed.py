import secrets
import hashlib

def bits_entropy():
    return secrets.token_bytes(16) # esadecimale 

bits=bits_entropy()
sha256=hashlib.sha256() # put inside sha256
sha256.update(bits)
sha256=sha256.hexdigest()
print(sha256)
