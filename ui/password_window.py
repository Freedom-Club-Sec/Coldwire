import tkinter as tk
from tkinter import messagebox
from ui.utils import (
        enhanced_entry
)

class PasswordWindow(tk.Toplevel):
    def __init__(self, master, callback):
        super().__init__(master)
        self.title("Password Required")
        self.configure(bg="black")
        self.resizable(False, False)
        self.callback = callback

        self.desc_label = tk.Label(self, text="A password is used to encrypt your account and contact information locally on the disk.", bg="black", fg="gray70", wraplength=300, justify="left")
        self.desc_label.pack(pady=(15, 5), padx=15)


        self.label = tk.Label(self, text="Enter password", bg="black", fg="white")
        self.label.pack(pady=(15, 5))

        self.password_entry = tk.Entry(self, bg="gray15", fg="white", insertbackground="white", width=30)
        self.password_entry.pack(pady=5)

        self.confirm_entry = tk.Entry(self, bg="gray15", fg="white", insertbackground="white", width=30)
        self.confirm_entry.pack(pady=5)

        enhanced_entry(self.password_entry, placeholder="Enter a 8 character password", show="*")
        enhanced_entry(self.confirm_entry, placeholder="Confirm the password", show="*")

        self.status_label = tk.Label(self, text="", fg="red", bg="black")
        self.status_label.pack(pady=(5, 0))

        self.submit_button = tk.Button(self, text="OK", command=self.submit, bg="gray25", fg="white")
        self.submit_button.pack(pady=(10, 15))

        self.bind("<Return>", lambda e: self.submit())
        self.transient(master)
        self.grab_set()
        self.wait_window(self)

    def submit(self):
        password = self.password_entry.get() if self.password_entry.cget("show") == "*" else None 
        confirm_password = self.confirm_entry.get() if self.confirm_entry.cget("show") == "*" else None

        if password != confirm_password:
            self.status_label.config(text="Passwords do not match.")
            return

        if password and len(password) < 8:
            if not messagebox.askyesno("No Password", "Password is less than 8 characters long, this is insecure. Are you sure you want to continue?"):
                return



        if not password:
            if not messagebox.askyesno("No Password", "You entered no password. Continue anyway?"):
                return

            if not messagebox.askyesno(
                "No Password", 
                "Disabling encryption allows anyone with access to your device to see your contacts, and cryptographic keys. Do this only in fully trusted environments. Are you absolutely sure?"
            ):
                return

        self.destroy()
        self.callback(password)


