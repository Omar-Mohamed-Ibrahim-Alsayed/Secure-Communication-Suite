import tkinter as tk
from blockCipher import AES
from ctr import CTR
import secrets
import hmac
import hashlib

class AES_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")

        self.input_label = tk.Label(self.root, text="Enter Text:")
        self.input_label.pack()

        self.input_text = tk.Text(self.root, height=5, width=50)
        self.input_text.pack()

        self.password_label = tk.Label(self.root, text="Enter Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        self.encrypt_button = tk.Button(
            self.root, text="Encrypt", command=self.encrypt_text
        )
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(
            self.root, text="Decrypt", command=self.decrypt_text
        )
        self.decrypt_button.pack()

    def encrypt_text(self):
        plaintext = self.input_text.get("1.0", "end-1c")
        password = self.password_entry.get()
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
        #messagebox.showinfo("Encryption", "Text encrypted successfully!")

    def decrypt_text(self):
        ciphertext = bytes.fromhex(self.input_text.get("1.0", "end-1c"))
        password = self.password_entry.get()
        salt = ciphertext[:16]
        nonce = ciphertext[16:26]
        ciphertext = ciphertext[26:-32]
        cipher = AES(password_str=password, salt=salt, key_len=256)


        mode = CTR(cipher, nonce)
        plaintext = mode.decrypt(ciphertext, 0)

        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", plaintext.decode())
        #messagebox.showinfo("Decryption", "Text decrypted successfully!")


if __name__ == "__main__":
    root = tk.Tk()
    aes_gui = AES_GUI(root)
    root.mainloop()
