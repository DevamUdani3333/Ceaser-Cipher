import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip

def encrypt_message():
    #Function to encrypt a plaintext message
    try:
        plaintext = plaintext_entry.get()
        shift = int(shift_entry.get())
        ciphertext = ""

        for char in plaintext:
            if char.isalpha():
                shift_amount = shift % 26
                if char.islower():
                    encrypted_char = chr(((ord(char) - ord('a') + shift_amount) % 26) + ord('a'))
                else:
                    encrypted_char = chr(((ord(char) - ord('A') + shift_amount) % 26) + ord('A'))
                ciphertext += encrypted_char
            else:
                ciphertext += char

        ciphertext_result.set(ciphertext)
    except ValueError:
        messagebox.showerror("Error", "Shift value must be an integer.")


def decrypt_message():
    #Function to decrypt a ciphertext message
    try:
        ciphertext = ciphertext_entry.get()
        shift = int(shift_entry.get())
        plaintext = ""

        for char in ciphertext:
            if char.isalpha():
                shift_amount = shift % 26
                if char.islower():
                    decrypted_char = chr(((ord(char) - ord('a') - shift_amount) % 26) + ord('a'))
                else:
                    decrypted_char = chr(((ord(char) - ord('A') - shift_amount) % 26) + ord('A'))
                plaintext += decrypted_char
            else:
                plaintext += char

        plaintext_result.set(plaintext)
    except ValueError:
        messagebox.showerror("Error", "Shift value must be an integer.")

def copy_to_clipboard(result):
    #Function to copy the result to the clipboard
    pyperclip.copy(result)

app = tk.Tk()
app.title("Caesar Cipher")

# Use a style from ttk for a more modern look
style = ttk.Style(app)
style.theme_use("clam")

app.geometry("400x300")

label_font = ("Helvetica", 12)
entry_font = ("Helvetica", 10)

plaintext_label = ttk.Label(app, text="Plaintext:", font=label_font)
ciphertext_label = ttk.Label(app, text="Ciphertext:", font=label_font)
shift_label = ttk.Label(app, text="Shift:", font=label_font)

plaintext_entry = ttk.Entry(app, font=entry_font)
ciphertext_entry = ttk.Entry(app, font=entry_font)
shift_entry = ttk.Entry(app, font=entry_font)

ciphertext_result = tk.StringVar()
plaintext_result = tk.StringVar()

ciphertext_result_label = ttk.Label(app, textvariable=ciphertext_result, font=label_font)
plaintext_result_label = ttk.Label(app, textvariable=plaintext_result, font=label_font)

encrypt_button = ttk.Button(app, text="Encrypt", command=encrypt_message)
decrypt_button = ttk.Button(app, text="Decrypt", command=decrypt_message)

copy_ciphertext_button = ttk.Button(app, text="Copy Ciphertext", command=lambda: copy_to_clipboard(ciphertext_result.get()))
copy_plaintext_button = ttk.Button(app, text="Copy Plaintext", command=lambda: copy_to_clipboard(plaintext_result.get()))

plaintext_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
ciphertext_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
shift_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

plaintext_entry.grid(row=0, column=1, padx=10, pady=5)
ciphertext_entry.grid(row=1, column=1, padx=10, pady=5)
shift_entry.grid(row=2, column=1, padx=10, pady=5)

encrypt_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")
decrypt_button.grid(row=3, column=1, padx=10, pady=10, sticky="e")

ciphertext_result_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")
plaintext_result_label.grid(row=4, column=1, padx=10, pady=5, sticky="e")

copy_ciphertext_button.grid(row=5, column=0, padx=10, pady=10, sticky="w")
copy_plaintext_button.grid(row=5, column=1, padx=10, pady=10, sticky="e")

app.mainloop()
