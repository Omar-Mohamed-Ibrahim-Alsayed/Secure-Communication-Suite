from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
    


class DESCipher(object):

    def __init__(self, key):
        self.key = key.encode()
        self.bs = DES.block_size
        self.cipher = DES.new(self.key, DES.MODE_ECB)

    def encrypt(self, raw):
        raw = pad(raw.encode(), self.bs)
        encrypted = self.cipher.encrypt(raw)
        return base64.b64encode(encrypted)

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        decrypted = self.cipher.decrypt(enc)
        return unpad(decrypted, self.bs).decode()


