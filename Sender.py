import socket
from used_models.blockCiphers import AESCipher
from used_models.PKC import RSAKeyExchange
from used_models.authentication import Authenticator 
import time
import cryptography.hazmat.primitives.serialization
from used_models.keyManagement import KeyManager
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend


sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_address = ('127.0.0.1', 8888)
sender_socket.connect(receiver_address)


# User Authentication

# authenticated = False
# while not authenticated:
#     choice = input("Do you want to [1] Sign Up or [2] Sign In? Enter 1 or 2: ")

#     if choice == '1':  # Sign Up
#         username = input("Enter a new username: ")
#         password = input("Enter a password: ")
#         if Authenticator.signup(username, password):
#             print("Signup successful.")
#             authenticated = True
#         else:
#             print("Username already exists. Please choose a different username.")

#     elif choice == '2':  # Sign In
#         username = input("Enter your username: ")
#         password = input("Enter your password: ")
#         if Authenticator.signin(username, password):
#             print("Signin successful.")
#             authenticated = True
#         else:
#             print("Invalid username or password.")

#     else:
#         print("Invalid choice.")



km = KeyManager()

# Exchanging public keys
received_public_key_bytes = sender_socket.recv(4096)
received_public_key = load_pem_public_key(received_public_key_bytes, backend=default_backend())

# Key Generation 
keys = km.generate_keys()
pub = keys.public_key().public_bytes(
    encoding=Encoding.PEM, 
    format=PublicFormat.SubjectPublicKeyInfo 
)
sender_socket.send(pub)
time.sleep(1)
# Generate and send certificate 
sender_certificate = Authenticator.generate_self_signed_certificate(keys, "sender_cert")
print('Generated cert')
sender_socket.send(sender_certificate.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM))
print('Sent cert')

symmetric_key = km.generate_symm(received_public_key_bytes)

keys = km.load_decrypted_keys('encrypted_keys.bin')
print('Got keys')

plaintext_message = input("Enter the message you want to send: ")  

# Encryption

aes_cipher = AESCipher(symmetric_key)

rsa_key_exchange = RSAKeyExchange()

encrypted_message = aes_cipher.encrypt(plaintext_message)

rsa_key_exchange.set_received_public_key(received_public_key_bytes)


try:
    encrypted_symmetric_key = rsa_key_exchange.encrypt_symmetric_key(symmetric_key, received_public_key_bytes)

    padded_encrypted_symmetric_key = encrypted_symmetric_key + b'\0' * (256 - len(encrypted_symmetric_key))

    sender_socket.send(encrypted_message)
    time.sleep(1)
    sender_socket.send(padded_encrypted_symmetric_key)
    print("Sent")

    sender_socket.close()
except ValueError as e:
    print("Error decrypting symmetric key or message:", e)
