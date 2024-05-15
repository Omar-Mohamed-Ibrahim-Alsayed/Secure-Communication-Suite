import socket
from used_models.blockCiphers import AESCipher
from used_models.PKC import RSAKeyExchange
from used_models.authentication import Authenticator  
from used_models.keyManagement import KeyManager  
import cryptography.x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat, PrivateFormat, NoEncryption

receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_address = ('127.0.0.1', 8888)
receiver_socket.bind(receiver_address)
receiver_socket.listen(1)

print("Waiting for connection...")
sender_socket, sender_address = receiver_socket.accept()
print("Connection established with:", sender_address)

# User Authentication
authenticated = False
while not authenticated:
    choice = input("Do you want to [1] Sign Up or [2] Sign In? Enter 1 or 2: ")

    if choice == '1':  # Sign Up
        username = input("Enter a new username: ")
        password = input("Enter a password: ")
        if Authenticator.signup(username, password):
            print("Signup successful.")
            authenticated = True
        else:
            print("Username already exists. Please choose a different username.")

    elif choice == '2':  # Sign In
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        if Authenticator.signin(username, password):
            print("Signin successful.")
            authenticated = True
        else:
            print("Invalid username or password.")

    else:
        print("Invalid choice.")



rsa_key_exchange = RSAKeyExchange()
km = KeyManager()

#Key generation and storing for RSAKeyExchange
keys = km.generate_keys()
priv =keys.private_bytes( encoding=Encoding.PEM,  
                                format=PrivateFormat.PKCS8, 
                                encryption_algorithm=NoEncryption() 
                            )
pub = keys.public_key().public_bytes(
    encoding=Encoding.PEM, 
    format=PublicFormat.SubjectPublicKeyInfo 
)

#Sending pub key to sender
sender_socket.send(pub)

rsa_key_exchange.set_received_public_key( pub)
rsa_key_exchange.set_received_private_key(priv)

#Receiving pub key of sender
received_public_key_bytes = sender_socket.recv(4096) 
received_public_key = load_pem_public_key(received_public_key_bytes, backend=default_backend())

#Receiving certificate from sender
certificate_bytes = sender_socket.recv(4096)
certificate = cryptography.x509.load_pem_x509_certificate(certificate_bytes, default_backend())

#Verifing certificate from sender
if Authenticator.verify_certificate(certificate_bytes, received_public_key):
    print("Certificate verified successfully.")
else:
    #if not verified ignore and close socket
    print("Certificate verification failed. Closing connection.")
    sender_socket.close()
    receiver_socket.close()
    exit()

#Get encrypted message
encrypted_message = sender_socket.recv(4096)

#Get encrypted symm key
padded_encrypted_symmetric_key = sender_socket.recv(4096)
encrypted_symmetric_key = padded_encrypted_symmetric_key.rstrip(b'\0')

try:
    #Decrypt symm key
    decrypted_symmetric_key = rsa_key_exchange.decrypt_symmetric_key(encrypted_symmetric_key)

    #Decrypt message
    aes_cipher = AESCipher(decrypted_symmetric_key)
    decrypted_message = aes_cipher.decrypt(encrypted_message)
    print("Decrypted Message with AES:", decrypted_message) 

except ValueError as e:
    print("Error decrypting symmetric key or message:", e)
    import traceback
    traceback.print_exc()  

sender_socket.close()
receiver_socket.close()
