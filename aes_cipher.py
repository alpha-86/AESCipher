import base64
import sys
from Crypto.Cipher import AES

class AESCipher:
    block_size = AES.block_size
    zero_padding = 1
    PKCS5Padding = 2
    PKCS7Padding = 3
    def __init__(self, key, mode = AES.MODE_ECB):
        if type(key) != bytes:
            key = bytes(key, 'utf-8')
        self.key = key
        self.aes = AES.new(self.key, mode)

    @classmethod
    def padding(cls, data, padding_type):
        PKCS7Padding = lambda s: s + (cls.block_size - len(s) % cls.block_size) * \
                chr(cls.block_size - len(s) % cls.block_size)
        if padding_type == cls.PKCS5Padding or \
                padding_type == cls.PKCS7Padding:
            return PKCS7Padding(data)
        if padding_type == cls.zero_padding:
            return data

    @classmethod
    def unpadding(cls, data, padding_type):
        #PKCS7Unpadding = lambda s : s[0:-ord(s[-1])]
        PKCS7Unpadding = lambda s : s[0:-s[-1]]
        if padding_type == cls.PKCS5Padding or \
                padding_type == cls.PKCS7Padding:
            return PKCS7Unpadding(data)
        if padding_type == cls.zero_padding:
            return data

    def encrypt(self, raw):
        raw = AESCipher.padding(raw, self.PKCS5Padding).encode("utf-8")
        return self.aes.encrypt(raw)

    def decrypt(self, enc):
        return self.unpadding(self.aes.decrypt(enc), self.PKCS5Padding).decode('utf8')


key = '1234567890123456'
aes = AESCipher(key)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    enc = aes.encrypt(line)
    print(enc)
    print("\n")
    raw = aes.decrypt(enc)
    print(raw)
    print("\n")


