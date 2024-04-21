import tkinter as tk
from tkinter import ttk, messagebox
from blockCipher import AES
import base64

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption and Decryption")
        
        self.password_label = ttk.Label(root, text="Password:")
        self.password_entry = ttk.Entry(root, show="*")
        self.text_label = ttk.Label(root, text="Text:")
        self.text_entry = tk.Text(root, height=5, width=50)
        self.encrypt_button = ttk.Button(root, text="Encrypt", command=self.encrypt_text)
        self.decrypt_button = ttk.Button(root, text="Decrypt", command=self.decrypt_text)
        self.result_label = ttk.Label(root, text="Result:")
        self.result_entry = tk.Text(root, height=5, width=50, state="disabled")
        
        self.password_label.pack(pady=5)
        self.password_entry.pack(pady=5)
        self.text_label.pack(pady=5)
        self.text_entry.pack(pady=5)
        self.encrypt_button.pack(pady=5)
        self.decrypt_button.pack(pady=5)
        self.result_label.pack(pady=5)
        self.result_entry.pack(pady=5)
        
    def encrypt_text(self):
        password = self.password_entry.get()
        text = self.text_entry.get("1.0", tk.END).strip()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        
        if not text:
            messagebox.showerror("Error", "Please enter text to encrypt.")
            return
        
        aes = AES(password, b'salt', key_len=256)  # You can change key_len as needed
        encrypted_text = aes.encrypt(text.encode())
        encoded_text = base64.b64encode(encrypted_text).decode()
        
        self.result_entry.config(state="normal")
        self.result_entry.delete("1.0", tk.END)
        self.result_entry.insert(tk.END, encoded_text)
        self.result_entry.config(state="disabled")
    
    def decrypt_text(self):
        password = self.password_entry.get()
        encoded_text = self.result_entry.get("1.0", tk.END).strip()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        
        if not encoded_text:
            messagebox.showerror("Error", "Please enter text to decrypt.")
            return
        
        try:
            encrypted_text = base64.b64decode(encoded_text)
        except:
            messagebox.showerror("Error", "Invalid base64 encoded text.")
            return
        
        aes = AES(password, b'salt', key_len=256)  # You can change key_len as needed
        decrypted_text = aes.decrypt(encrypted_text, b'salt', key_len=256)
        
        self.text_entry.delete("1.0", tk.END)
        self.text_entry.insert(tk.END, decrypted_text.decode())

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()
