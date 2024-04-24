import tkinter as tk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket

class ReceiverGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Receiver")
        
        self.label = tk.Label(root, text="Received Message:")
        self.label.pack()
        
        self.textbox = tk.Text(root, width=50, height=10)
        self.textbox.pack()
        
        self.start_server()
        
    def start_server(self):
        # Start a socket server to receive messages
        host = 'localhost'
        port = 12345
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                encrypted_message = conn.recv(1024)
                decrypted_message = self.decrypt_message(encrypted_message)
                self.textbox.insert(tk.END, decrypted_message.decode())
    
    def decrypt_message(self, encrypted_message):
        # Decrypt the message using RSA
        # Replace 'private_key' with the receiver's private key
        private_key = ''' Replace this with the receiver's private key '''
        key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        decrypted_message = cipher_rsa.decrypt(encrypted_message)
        return decrypted_message

if __name__ == "__main__":
    root = tk.Tk()
    receiver_gui = ReceiverGUI(root)
    root.mainloop()
