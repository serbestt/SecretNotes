from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt_notes():
    title = title_entry.get()
    message = input_text.get("1.0", END)
    master_secret = master_secret_input.get()

    # Error Message Start
    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="HATA!!!", message="Tüm Bilgileri Giriniz.")
    else:
        # Encryption Start
        message_encrypted = encode(master_secret, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")

            # Save success message
            messagebox.showinfo(title="Başarılı", message="Not başarıyla kaydedildi!")

            # Clear entry fields after successful save
            title_entry.delete(0, END)
            input_text.delete("1.0", END)
            master_secret_input.delete(0, END)
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
                messagebox.showinfo(title="Başarılı", message="Not başarıyla kaydedildi!")

def decrypt_notes():
    message_encrypted = input_text.get("1.0", END)
    master_secret = master_secret_input.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="HATA!", message="LÜTFEN TÜM BİLGİLERİ GİRİNİZ")
    else:
        decrypted_message = decode(master_secret, message_encrypted)
        input_text.delete("1.0", END)
        input_text.insert("1.0", decrypted_message)

# Arayüz
FONT = ("verdana", 20, "normal")
window = Tk()
window.title("Gizli Not")
window.config(padx=20, pady=40)

# Kullanıcı Start
title_info_label = Label(window, text="Enter Title", font=("verdana", 20, "normal"))
title_info_label.pack()  # Label'ı pencereye yerleştir

title_entry = Entry(width=40)
title_entry.pack()
# Kullanıcı End

# Not Bölümü Start
input_info_label = Label(text="Enter your secret", font=FONT)
input_info_label.pack()

input_text = Text()
input_text.pack()
# Not Bölümü End

# Şifreleme Start
master_secret_label = Label(text="Master Key", font=FONT)
master_secret_label.pack()

master_secret_input = Entry(width=40)
master_secret_input.pack()
# Şifre End

# Save buton Start
save_button = Button(text="Save & Encrypt", command=save_and_encrypt_notes)
save_button.pack()
# Save buton End

# Decrypt button Start
decrypt_button = Button(text="Decrypt", command=decrypt_notes)
decrypt_button.pack()
# Decrypt button End

window.mainloop()
