import tkinter as tk
import socket
from used_models.blockCiphers import AESCipher
from used_models.PKC import RSAKeyExchange
from used_models.authentication import Authenticator
import time
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class ReceiverApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Receiver Application")
        self.master.configure(bg="#EFEFEF")  # Light gray background

        self.label_username = tk.Label(master, text="Username:", bg="#EFEFEF", fg="#333333", font=("Arial", 12))
        self.label_username.pack()
        self.entry_username = tk.Entry(master, bg="white", fg="#333333", font=("Arial", 12))
        self.entry_username.pack()

        self.label_password = tk.Label(master, text="Password:", bg="#EFEFEF", fg="#333333", font=("Arial", 12))
        self.label_password.pack()
        self.entry_password = tk.Entry(master, show="*", bg="white", fg="#333333", font=("Arial", 12))
        self.entry_password.pack()

        self.button_signup = tk.Button(master, text="Sign Up", command=self.signup, bg="#EFEFEF", fg="black", font=("Arial", 12))
        self.button_signup.pack()
        self.button_signin = tk.Button(master, text="Sign In ", command=self.signin, bg="#EFEFEF", fg="black", font=("Arial", 12))
        self.button_signin.pack()

        self.label_message = tk.Label(master, text="Received Message:", bg="#EFEFEF", fg="#333333", font=("Arial", 12))
        self.label_message.pack()
        self.text_received_message = tk.Text(master, height=5, bg="white", fg="#333333", font=("Arial", 12))
        self.text_received_message.pack()

        self.label_info = tk.Label(master, text="", bg="#EFEFEF", fg="#333333", font=("Arial", 12))
        self.label_info.pack()

        self.aes_cipher = AESCipher("aes_key")
        self.rsa_key_exchange = RSAKeyExchange()
        self.authenticated = False

        self.receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.receiver_address = ('127.0.0.1', 8888)
        self.receiver_socket.bind(self.receiver_address)
        self.receiver_socket.listen(1)

        self.button_receive = tk.Button(master, text="Receive Message", command=self.receive_message, bg="#F39C12", fg="white", font=("Arial", 12))
        self.button_receive.pack()

    def signup(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        if Authenticator.signup(username, password):
            self.label_info.config(text="Signup successful.", fg="#2ECC71")  # Information message in green
        else:
            self.label_info.config(text="Username already exists. Please choose a different username.", fg="#E74C3C")  # Error message in red

    def signin(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        if Authenticator.signin(username, password):
            self.label_info.config(text="Signin successful.", fg="#2ECC71")  # Information message in green
            self.authenticated = True
        else:
            self.label_info.config(text="Invalid username or password.", fg="#E74C3C")  # Error message in red

    def receive_message(self):
        if not self.authenticated:
            self.label_info.config(text="Authentication required. Please sign in or sign up.", fg="#E74C3C")  # Error message in red
            return

        try:
            print("Waiting for connection...")
            sender_socket, sender_address = self.receiver_socket.accept()
            print("Connection established with:", sender_address)

            
            rsa_key_exchange = RSAKeyExchange()
            public_key = rsa_key_exchange.get_public_key()
            sender_socket.send(public_key)

            received_public_key_bytes = sender_socket.recv(4096)  # Receive the public key bytes
            received_public_key = load_pem_public_key(received_public_key_bytes, backend=default_backend())


            certificate_bytes = sender_socket.recv(4096)
            certificate = cryptography.x509.load_pem_x509_certificate(certificate_bytes, default_backend())

            if Authenticator.verify_certificate(certificate_bytes, received_public_key):
                print("Certificate verified successfully.")
            else:
                print("Certificate verification failed. Closing connection.")
                sender_socket.close()
                self.receiver_socket.close()
                exit()
            encrypted_message = sender_socket.recv(4096)

            padded_encrypted_symmetric_key = sender_socket.recv(4096)
            encrypted_symmetric_key = padded_encrypted_symmetric_key.rstrip(b'\0')

            try:
                decrypted_symmetric_key = rsa_key_exchange.decrypt_symmetric_key(encrypted_symmetric_key)

                aes_cipher = AESCipher(decrypted_symmetric_key)
                decrypted_message = aes_cipher.decrypt(encrypted_message)
                print("Decrypted Message with AES:", decrypted_message)

            except ValueError as e:
                print("Error decrypting symmetric key or message:", e)

            sender_socket.close()
            self.receiver_socket.close()


            self.text_received_message.delete(1.0, tk.END)
            self.text_received_message.insert(tk.END, decrypted_message)
            self.label_info.config(text="Message received successfully.", fg="#2ECC71")  # Information message in green

            sender_socket.close()

        except Exception as e:
            self.label_info.config(text=f"Error: {e}", fg="#E74C3C")  # Error message in red


def main():
    root = tk.Tk()
    app = ReceiverApp(root)
    root.geometry("600x400")
    root.mainloop()

if __name__ == "__main__":
    main()
