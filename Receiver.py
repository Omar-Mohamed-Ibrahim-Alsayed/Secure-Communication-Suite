import socket
from used_models.blockCiphers import AESCipher
from used_models.ASCipher import RSAKeyExchange

# Create a socket
receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_address = ('127.0.0.1', 8888)  # Use the same port as the sender
receiver_socket.bind(receiver_address)
receiver_socket.listen(1)

# Accept incoming connection
print("Waiting for connection...")
sender_socket, sender_address = receiver_socket.accept()
print("Connection established with:", sender_address)

# Instantiate block cipher objects
aes_cipher = AESCipher("your_aes_key")  # Consider secure key generation

# Instantiate public key crypto objects
rsa_key_exchange = RSAKeyExchange()

# Receive the public key from the sender
received_public_key = sender_socket.recv(4096)

print("received_public_key:", received_public_key)

# Set the received public key directly without decoding
rsa_key_exchange.set_received_public_key(received_public_key)



# Receive the encrypted message
encrypted_message = sender_socket.recv(4096)  # Increased buffer size
print("Received Encrypted Message:", encrypted_message)

# Receive the padded encrypted symmetric key
# Increase the buffer size to accommodate larger keys if needed
padded_encrypted_symmetric_key = sender_socket.recv(4096)  # Assuming fixed key length, adjust if needed

# Debugging output to inspect received data
print("Received Encrypted Symmetric Key with RSA:", padded_encrypted_symmetric_key)

# Trim the padding from the received encrypted symmetric key
encrypted_symmetric_key = padded_encrypted_symmetric_key.rstrip(b'\0')


try:
    # decrypted_symmetric_key = rsa_key_exchange.decrypt_symmetric_key(encrypted_symmetric_key)
    # print("Decrypted Symmetric Key with RSA:", decrypted_symmetric_key.decode())

    # Decrypt the message using the decrypted symmetric key
    decrypted_message = aes_cipher.decrypt(encrypted_message)
    print("Decrypted Message with AES:", decrypted_message)

except ValueError as e:
    print("Error decrypting symmetric key or message:", e)

sender_socket.close()
receiver_socket.close()