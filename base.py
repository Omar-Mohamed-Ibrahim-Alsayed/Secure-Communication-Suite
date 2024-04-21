import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import queue

GlobalKey = get_random_bytes(16) 

class EncryptionWorker(threading.Thread):
    def __init__(self, plaintext_queue, ciphertext_queue):
        threading.Thread.__init__(self)
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue
        self.key = GlobalKey  # AES key must be either 16, 24, or 32 bytes long
        self.cipher = AES.new(self.key, AES.MODE_EAX)

    def run(self):
        while True:
            plaintext = self.plaintext_queue.get()
            if plaintext is None:
                break
            ciphertext, tag = self.cipher.encrypt_and_digest(plaintext)
            self.ciphertext_queue.put((ciphertext, tag))

class DecryptionWorker(threading.Thread):
    def __init__(self, ciphertext_queue, decrypted_queue, key):
        threading.Thread.__init__(self)
        self.ciphertext_queue = ciphertext_queue
        self.decrypted_queue = decrypted_queue
        self.key = key  # AES key for decryption
        self.cipher = AES.new(self.key, AES.MODE_EAX)

    def run(self):
        while True:
            ciphertext, tag = self.ciphertext_queue.get()
            if ciphertext is None:
                break
            try:
                decrypted_text = self.cipher.decrypt_and_verify(ciphertext, tag).decode()
                self.decrypted_queue.put(decrypted_text)
            except ValueError:
                print("Decryption failed (wrong key or tampered data).")

# Usage:
plaintext_queue = queue.Queue()
ciphertext_queue = queue.Queue()
worker = EncryptionWorker(plaintext_queue, ciphertext_queue)
worker.start()
worker.join()
worker2 = DecryptionWorker(plaintext_queue, ciphertext_queue)
worker2.start()
worker2.join()
