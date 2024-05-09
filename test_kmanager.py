from used_models.keyManagement import KeyManager
import time

key_storage = KeyManager()

# Example keys to store
keys_to_store = {
    'aes_key': 'your_aes_encryption_key',
    'rsa_private_key': 'your_rsa_private_key',
    'other_key': 'other_value'
}

key_storage.store_encrypted_keys(keys_to_store, 'encrypted_keys.bin')

time.sleep(60)

decrypted_keys = key_storage.load_decrypted_keys('encrypted_keys.bin')
print("Decrypted Keys:", decrypted_keys)
