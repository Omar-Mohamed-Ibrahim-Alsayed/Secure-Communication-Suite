import tkinter as tk
from used_models.blockCiphers import AESCipher  # Import AESCipher from your block cipher file
from used_models.ASCipher import RSAKeyExchange  # Import RSAKeyExchange from your public key cryptosystem file
import socket

class SenderGUI:
    def __init__(self, root):
        self.aes_cipher = AESCipher('your_aes_key')
        self.rsa_key_exchange = RSAKeyExchange()
        self.root = root
        self.root.title("Sender")
        
        self.label = tk.Label(root, text="Enter your message:")
        self.label.pack()
        
        self.entry = tk.Entry(root, width=50)
        self.entry.pack()
        
        self.encrypt_button = tk.Button(root, text="Encrypt and Send", command=self.encrypt_and_send)
        self.encrypt_button.pack()


    def encrypt_and_send(self):
        # Encrypt the message using AES
        message = self.entry.get()
        encrypted_message = self.aes_cipher.encrypt(message)

        # Encrypt the AES key using RSA
        recipient_public_key = 'recipient_public_key'
        encrypted_aes_key = self.rsa_key_exchange.encrypt_symmetric_key(self.aes_cipher.key, recipient_public_key)

        # Combine encrypted message and AES key
        combined_message = encrypted_aes_key + b'|' + encrypted_message

        # Send the combined message to the receiver
        self.send_message(combined_message)

    def send_message(self, message):
        # Establish a socket connection and send the message to the receiver
        # Replace 'host' and 'port' with appropriate values
        host = 'localhost'
        port = 12345
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(message)

if __name__ == "__main__":
    root = tk.Tk()
    sender_gui = SenderGUI(root)
    root.mainloop()
