import socket
from used_models.blockCiphers import AESCipher
from used_models.PKC import RSAKeyExchange
import time

receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_address = ('127.0.0.1', 8888)
receiver_socket.bind(receiver_address)
receiver_socket.listen(1)

print("Waiting for connection...")
sender_socket, sender_address = receiver_socket.accept()
print("Connection established with:", sender_address)

rsa_key_exchange = RSAKeyExchange()
public_key = rsa_key_exchange.get_public_key()
sender_socket.send(public_key)
time.sleep(1)

encrypted_message = sender_socket.recv(4096)
print("Received Encrypted Message:", encrypted_message)

padded_encrypted_symmetric_key = sender_socket.recv(4096)
encrypted_symmetric_key = padded_encrypted_symmetric_key.rstrip(b'\0')
print("Received Encrypted Symmetric Key with RSA:", encrypted_symmetric_key)

try:
    decrypted_symmetric_key = rsa_key_exchange.decrypt_symmetric_key(encrypted_symmetric_key)
    print("Decrypted Symmetric Key with RSA:", decrypted_symmetric_key)

    aes_cipher = AESCipher(decrypted_symmetric_key)
    decrypted_message = aes_cipher.decrypt(encrypted_message)
    print("Decrypted Message with AES:", decrypted_message)

except ValueError as e:
    print("Error decrypting symmetric key or message:", e)

sender_socket.close()
receiver_socket.close()
