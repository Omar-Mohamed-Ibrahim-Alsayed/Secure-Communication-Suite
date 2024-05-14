import tkinter as tk
from tkinter import messagebox
import socket
from used_models.blockCiphers import AESCipher
from used_models.PKC import RSAKeyExchange
from used_models.keyManagement import KeyManager
from used_models.authentication import Authenticator
import time
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.x509
from cryptography.hazmat.backends import default_backend

class SenderApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Sender Application")
        self.master.configure(bg="#EFEFEF")  # Light gray background

        self.label_username = tk.Label(master, text="Username:", bg="#EFEFEF", fg="#333333", font=("Arial", 12))
        self.label_username.pack()
        self.entry_username = tk.Entry(master, bg="white", fg="#333333", font=("Arial", 12))
        self.entry_username.pack()

        self.label_password = tk.Label(master, text="Password:", bg="#EFEFEF", fg="#333333", font=("Arial", 12))
        self.label_password.pack()
        self.entry_password = tk.Entry(master, show="*", bg="white", fg="#333333", font=("Arial", 12))
        self.entry_password.pack()

        self.button_signup = tk.Button(master, text="Sign Up", command=self.signup, bg="#3498DB", fg="white", font=("Arial", 12))
        self.button_signup.pack()
        self.button_signin = tk.Button(master, text="Sign In", command=self.signin, bg="#2ECC71", fg="white", font=("Arial", 12))
        self.button_signin.pack()

        self.label_message = tk.Label(master, text="Message:", bg="#EFEFEF", fg="#333333", font=("Arial", 12))
        self.label_message.pack()
        self.entry_message = tk.Entry(master, bg="white", fg="#333333", font=("Arial", 12))
        self.entry_message.pack()

        self.label_info = tk.Label(master, text="", bg="#EFEFEF", fg="#333333", font=("Arial", 12))
        self.label_info.pack()

        self.button_send = tk.Button(master, text="Send Message", command=self.send_message, bg="#F39C12", fg="white", font=("Arial", 12))
        self.button_send.pack()

        self.aes_cipher = AESCipher("aes_key")
        self.rsa_key_exchange = RSAKeyExchange()
        self.authenticated = False
        
        self.sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.receiver_address = ('127.0.0.1', 8888)
        self.sender_socket.connect(self.receiver_address)

    def signup(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        if Authenticator.signup(username, password):
            self.label_info.config(text="Signup successful.", fg="#2ECC71")   
        else:
            self.label_info.config(text="Username already exists. Please choose a different username.", fg="#E74C3C")  # Error message in red

    def signin(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        if Authenticator.signin(username, password):
            self.label_info.config(text="Signin successful.", fg="#2ECC71")   
            self.authenticated = True
        else:
            self.label_info.config(text="Invalid username or password.", fg="#E74C3C")  # Error message in red

    def send_message(self):
        if not self.authenticated:
            self.label_info.config(text="Authentication required. Please sign in or sign up.", fg="#E74C3C")  # Error message in red
            return

        plaintext_message = self.entry_message.get()

        try:   
            km = KeyManager()

            # Exchanging public keys
            received_public_key = self.sender_socket.recv(4096)

            # Key Generation 
            keys = km.generate_keys()

            # Generate certificate using the correct public key
            cert_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            sender_certificate = Authenticator.generate_self_signed_certificate(cert_key, "sender_cert")
            print('Generated cert')
            self.sender_socket.send(sender_certificate.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM))
            print('Sent cert')

            symmetric_key = km.generate_symm(received_public_key)

            keys = km.load_decrypted_keys('encrypted_keys.bin')
            print('Got keys')
            
            # Encryption

            aes_cipher = AESCipher(symmetric_key)

            rsa_key_exchange = RSAKeyExchange()

            encrypted_message = aes_cipher.encrypt(plaintext_message)

            rsa_key_exchange.set_received_public_key(received_public_key)

            encrypted_symmetric_key = rsa_key_exchange.encrypt_symmetric_key(symmetric_key, received_public_key)

            padded_encrypted_symmetric_key = encrypted_symmetric_key + b'\0' * (256 - len(encrypted_symmetric_key))

            self.sender_socket.send(encrypted_message)
            time.sleep(1)
            self.sender_socket.send(padded_encrypted_symmetric_key)

            self.sender_socket.close()

            self.label_info.config(text="Message sent successfully.", fg="#2ECC71")   

        except Exception as e:
            self.label_info.config(text=f"Error: {e}", fg="#E74C3C")  # Error message in red


def main():
    root = tk.Tk()
    app = SenderApp(root)
    root.geometry("600x400")
    root.mainloop()

if __name__ == "__main__":
    main()
