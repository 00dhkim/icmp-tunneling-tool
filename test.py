from Crypto.Cipher import AES
from secrets import token_bytes

# key length must be 32
# key = 'happynewyear2022happynewyear2022'.encode('ascii')
key = token_bytes(32)

BLOCK_SIZE = 16

def encrypt(msg: str):
    
    def _pad(s):
        return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
    msg = _pad(msg)
    
    iv = bytes([0x00] * 16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(msg.encode('utf-8'))
    return ciphertext

def decrypt(ciphertext):
    
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
    
    iv = bytes([0x00] * 16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    return _unpad(plaintext.decode('utf-8'))




ciphertext = encrypt('김도현김도현김도현김도현김도현김도현김도현김도현김도현김도현')
plaintext = decrypt(ciphertext)
print(f'Cipher text: {ciphertext}')
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plain text: {plaintext}')