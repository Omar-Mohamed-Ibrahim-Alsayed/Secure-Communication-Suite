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
print(encrypted_aes)
print(decrypted_aes)
encrypted_des = des_cipher.encrypt(plaintext_message)
decrypted_des = des_cipher.decrypt(encrypted_des)
print(encrypted_des)
print(decrypted_des)

# Key exchange example (using RSA for simplicity)
alice_public_key = rsa_key_exchange.get_public_key()
bob_encrypted_symmetric_key = rsa_key_exchange.encrypt_symmetric_key(
    "shared_symmetric_key", alice_public_key
)
