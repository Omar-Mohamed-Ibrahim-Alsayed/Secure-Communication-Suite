import socket
import time
from used_models.PKC import RSAKeyExchange

hacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_address = ('127.0.0.1', 8888)
hacker_socket.bind(receiver_address)
hacker_socket.listen(1)

print("Hacker waiting for connection...")
receiver_socket, receiver_address = hacker_socket.accept()
print("Connection established with:", receiver_address)
rsa_key_exchange = RSAKeyExchange()

public_key = rsa_key_exchange.get_public_key()
receiver_socket.send(public_key)
time.sleep(1)

encrypted_message = receiver_socket.recv(4096)
print("Received Message:", encrypted_message)

receiver_socket.close()
hacker_socket.close()
