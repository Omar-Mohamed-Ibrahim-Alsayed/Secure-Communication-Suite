from used_models.blockCiphers import AESCipher, DESCipher
from used_models.ASCipher import RSAKeyExchange, ECCKeyExchange

# Instantiate block cipher objects
aes_cipher = AESCipher("your_aes_key")
des_cipher = DESCipher("your_des")

# Instantiate public key crypto objects
rsa_key_exchange = RSAKeyExchange()
ecc_key_exchange = ECCKeyExchange()

# Example usage
plaintext_message = "Hello, this is a secure message!"
encrypted_aes = aes_cipher.encrypt(plaintext_message)
decrypted_aes = aes_cipher.decrypt(encrypted_aes)
print("AES Encrypted:", encrypted_aes)
print("AES Decrypted:", decrypted_aes)

encrypted_des = des_cipher.encrypt(plaintext_message)
decrypted_des = des_cipher.decrypt(encrypted_des)
print("DES Encrypted:", encrypted_des)
print("DES Decrypted:", decrypted_des)

# Key exchange example (using RSA for simplicity)
alice_public_key = rsa_key_exchange.get_public_key()
bob_encrypted_symmetric_key = rsa_key_exchange.encrypt_symmetric_key(
    "shared_symmetric_key", alice_public_key
)
print("Encrypted Symmetric Key with RSA:", bob_encrypted_symmetric_key)

# Decrypting the symmetric key using RSA private key
decrypted_symmetric_key = rsa_key_exchange.decrypt_symmetric_key(
    bob_encrypted_symmetric_key
)
print("Decrypted Symmetric Key with RSA:", decrypted_symmetric_key)

# Now use the decrypted symmetric key for AES or DES encryption/decryption
encrypted_with_aes = aes_cipher.encrypt(decrypted_symmetric_key)
decrypted_with_aes = aes_cipher.decrypt(encrypted_with_aes)
print("AES Encrypted with Decrypted Symmetric Key:", encrypted_with_aes)
print("AES Decrypted with Decrypted Symmetric Key:", decrypted_with_aes)

encrypted_with_des = des_cipher.encrypt(decrypted_symmetric_key)
decrypted_with_des = des_cipher.decrypt(encrypted_with_des)
print("DES Encrypted with Decrypted Symmetric Key:", encrypted_with_des)
print("DES Decrypted with Decrypted Symmetric Key:", decrypted_with_des)
