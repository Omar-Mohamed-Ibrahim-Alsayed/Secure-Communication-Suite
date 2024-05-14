from used_models.keyManagement import KeyManager
import time

key_storage = KeyManager()

# Example keys to store
keys_to_store = 'key'

key_storage.store_encrypted_keys(keys_to_store, 'encrypted_keys.bin')


decrypted_keys = key_storage.load_decrypted_keys('encrypted_keys.bin')
print("Decrypted Keys:", decrypted_keys)
