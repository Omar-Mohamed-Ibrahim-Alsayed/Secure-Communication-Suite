import socket
from used_models.blockCiphers import AESCipher
from used_models.ASCipher import RSAKeyExchange
import time



# Create a socket
sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_address = ('127.0.0.1', 8888)  # Update the port to 8888
sender_socket.connect(receiver_address)

# Instantiate block cipher objects
aes_cipher = AESCipher("your_aes_key")  # Consider secure key generation

# Instantiate public key crypto objects
rsa_key_exchange = RSAKeyExchange()

# Generate a message to be sent
plaintext_message = "Hello, this is a secure message!"

# Encrypt the message using AES
encrypted_message = aes_cipher.encrypt(plaintext_message)

# Generate a symmetric key to be used for encryption
symmetric_key = "shared_symmetric_key"  # Consider secure key generation

# Get the public key from RSAKeyExchange
public_key = rsa_key_exchange.get_public_key()
# Encode the public key in PEM format before sending
sender_socket.send(public_key)
print(public_key)
time.sleep(1)


# Encrypt the symmetric key using RSA for key exchange
encrypted_symmetric_key = rsa_key_exchange.encrypt_symmetric_key(symmetric_key, public_key)

# Pad the encrypted symmetric key to a fixed length (e.g., 256 bytes for RSA 2048-bit keys)
padded_encrypted_symmetric_key = encrypted_symmetric_key + b'\0' * (256 - len(encrypted_symmetric_key))

# Send the encrypted message and the padded encrypted symmetric key to the receiver
sender_socket.send(encrypted_message)
time.sleep(1)

sender_socket.send(padded_encrypted_symmetric_key)

# Close the socket after sending
sender_socket.close()

