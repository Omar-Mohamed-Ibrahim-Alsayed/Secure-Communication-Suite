import json
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

class KeyManager:
    def __init__(self, master_key=None):
        if master_key is None:
            master_key = get_random_bytes(32)
        self.master_key = master_key
        self.cipher = AES.new(self.master_key, AES.MODE_EAX)
        self.key_rotation_interval = 2 * 60 
        self.last_rotation_time = time.time()  

    def generate_keys(self):
        key = RSA.generate(2048)
        self.last_rotation_time = time.time()  
        self.store_encrypted_keys(key, 'encrypted_keys.bin')
        public_key = key.publickey()
        return public_key

    def store_encrypted_keys(self, keys, filename):
        cipher_text, tag = self.cipher.encrypt_and_digest(json.dumps(keys).encode())
        with open(filename, 'wb') as file:
            file.write(self.cipher.nonce + tag + cipher_text)

    def load_decrypted_keys(self, filename):
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
        return json.loads(decrypted_data.decode())
