import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

class KeyManager:
    def __init__(self, master_key=None):
        if master_key is None:
            master_key = get_random_bytes(32)
        self.master_key = master_key
        self.cipher = AES.new(self.master_key, AES.MODE_EAX)
        self.key_rotation_interval = 2 * 60 
        self.last_rotation_time = time.time()

    def generate_keys(self):
        key = RSA.generate(1024)
        private_key_bytes = key.export_key()
        public_key_bytes = key.publickey().export_key()
        keys = {'private_key': private_key_bytes.decode('latin1'), 'public_key': public_key_bytes.decode('latin1')}
        self.last_rotation_time = time.time()
        self.store_encrypted_keys(keys, 'encrypted_keys.bin')
        return key
    
    def generate_symm(self,pub):
        salt = os.urandom(16)

        password = pub
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return str(key)

    def store_encrypted_keys(self, keys, filename):
        # Serialize the keys to JSON before encryption
        serialized_keys = json.dumps(keys).encode()
        cipher_text, tag = self.cipher.encrypt_and_digest(serialized_keys)
        with open(filename, 'wb') as file:
            file.write(self.cipher.nonce + tag + cipher_text)

    def load_decrypted_keys(self, filename):
        # Decrypt and deserialize the keys
        current_time = time.time()
        time_left = self.last_rotation_time + self.key_rotation_interval - current_time
        if current_time - self.last_rotation_time > self.key_rotation_interval:
            self.generate_keys()
            self.last_rotation_time = current_time
            time_left = self.key_rotation_interval

        print(f"Time left until key expires: {time_left:.2f} seconds")
        with open(filename, 'rb') as file:
            data = file.read()
        nonce, tag, cipher_text = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.master_key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(cipher_text, tag)
        keys = json.loads(decrypted_data.decode())
        private_key = RSA.import_key(keys['private_key'].encode('latin1'))
        public_key = RSA.import_key(keys['public_key'].encode('latin1'))
        return {'private_key': private_key, 'public_key': public_key}
