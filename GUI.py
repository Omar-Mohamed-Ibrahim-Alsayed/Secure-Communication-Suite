import tkinter as tk
from tkinter import ttk
from used_models.blockCiphers import AESCipher,DESCipher
from Crypto import Random

class AppGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption/Decryption Tool")

        self.label_key = ttk.Label(self.root, text="Enter Key:")
        self.label_key.pack()
        self.entry_key = ttk.Entry(self.root, show='*')
        self.entry_key.pack()

        self.label_text = ttk.Label(self.root, text="Enter Text:")
        self.label_text.pack()
        self.entry_text = ttk.Entry(self.root)
        self.entry_text.pack()

        self.btn_encrypt_aes = ttk.Button(self.root, text="Encrypt (AES)", command=self.encrypt_aes)
        self.btn_encrypt_aes.pack()
        self.btn_decrypt_aes = ttk.Button(self.root, text="Decrypt (AES)", command=self.decrypt_aes)
        self.btn_decrypt_aes.pack()

        self.btn_encrypt_des = ttk.Button(self.root, text="Encrypt (DES)", command=self.encrypt_des)
        self.btn_encrypt_des.pack()
        self.btn_decrypt_des = ttk.Button(self.root, text="Decrypt (DES)", command=self.decrypt_des)
        self.btn_decrypt_des.pack()

        self.output_label = ttk.Label(self.root, text="")
        self.output_label.pack()

    def encrypt_aes(self):
        key = self.entry_key.get()
        text = self.entry_text.get()
        cipher = AESCipher(key)
        encrypted = cipher.encrypt(text)
        self.output_label.config(text=f"Encrypted (AES): {encrypted.decode()}")

    def decrypt_aes(self):
        key = self.entry_key.get()
        text = self.entry_text.get()
        cipher = AESCipher(key)
        decrypted = cipher.decrypt(text.encode())
        self.output_label.config(text=f"Decrypted (AES): {decrypted}")

    def encrypt_des(self):
        key = self.entry_key.get()
        text = self.entry_text.get()
        cipher = DESCipher(key)
        encrypted = cipher.encrypt(text)
        self.output_label.config(text=f"Encrypted (DES): {encrypted.decode()}")

    def decrypt_des(self):
        key = self.entry_key.get()
        text = self.entry_text.get()
        cipher = DESCipher(key)
        decrypted = cipher.decrypt(text.encode())
        self.output_label.config(text=f"Decrypted (DES): {decrypted}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()