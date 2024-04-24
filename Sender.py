import socket
from used_models.blockCiphers import AESCipher
from used_models.PKC import RSAKeyExchange
import time

sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_address = ('127.0.0.1', 8888)
sender_socket.connect(receiver_address)

aes_cipher = AESCipher("aes_key")

rsa_key_exchange = RSAKeyExchange()

plaintext_message = "Hello, this is a secure message!"
encrypted_message = aes_cipher.encrypt(plaintext_message)

symmetric_key = "aes_key"

received_public_key = sender_socket.recv(4096)

rsa_key_exchange.set_received_public_key(received_public_key)

encrypted_symmetric_key = rsa_key_exchange.encrypt_symmetric_key(symmetric_key, received_public_key)
padded_encrypted_symmetric_key = encrypted_symmetric_key + b'\0' * (256 - len(encrypted_symmetric_key))

sender_socket.send(encrypted_message)
time.sleep(1)
sender_socket.send(padded_encrypted_symmetric_key)

sender_socket.close()
