import tkinter as tk
from blockCipher import AES
import secrets
import hmac
from PKC import generate_keys
import hashlib
from utilities.ctr import CTR


class AES_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")
        self.root.config(bg="#333333")  # Dark background color

        self.input_label = tk.Label(self.root, text="Enter Text:", font=("Arial", 12), bg="#333333", fg="#ffffff")  # White text on dark background
        self.input_label.pack(pady=10)

        self.input_text = tk.Text(self.root, height=5, width=50, font=("Arial", 10), bg="#555555", fg="#ffffff")  # White text on dark background
        self.input_text.pack(padx=10)

        _ , self.password = generate_keys()

        self.encrypt_button = tk.Button(
            self.root, text="Encrypt", command=self.encrypt_text, font=("Arial", 12), bg="#007bff", fg="#ffffff"  # Blue background with white text
        )
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(
            self.root, text="Decrypt", command=self.decrypt_text, font=("Arial", 12), bg="#dc3545", fg="#ffffff"  # Red background with white text
        )
        self.decrypt_button.pack(pady=5)

    def encrypt_text(self):
        plaintext = self.input_text.get("1.0", "end-1c")
        password = self.password
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(10)
        cipher = AES(password_str=password, salt=salt, key_len=256)
        mode = CTR(cipher, nonce)
        ciphertext = salt + nonce + mode.encrypt(plaintext.encode(), 0)
        hmac_val = hmac.digest(
            key=cipher.hmac_key, msg=ciphertext, digest=hashlib.sha256
        )
        ciphertext += hmac_val

        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", ciphertext.hex())

    def decrypt_text(self):
        ciphertext = bytes.fromhex(self.input_text.get("1.0", "end-1c"))
        password = self.password
        salt = ciphertext[:16]
        nonce = ciphertext[16:26]
        ciphertext = ciphertext[26:-32]
        cipher = AES(password_str=password, salt=salt, key_len=256)

        mode = CTR(cipher, nonce)
        plaintext = mode.decrypt(ciphertext, 0)

        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", plaintext.decode())

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("500x400")
    aes_gui = AES_GUI(root)
    root.mainloop()
