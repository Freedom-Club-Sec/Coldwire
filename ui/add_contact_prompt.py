from tkinter import messagebox
from ui.utils import *
from logic.get_user import check_if_contact_exists
from logic.contacts import save_contact
from logic.storage import save_account_data
import tkinter as tk
import logging

logger = logging.getLogger(__name__)

class AddContactPrompt(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Add Contact")
        self.geometry("250x150")
        self.configure(bg="black")
        self.resizable(False, False)

        tk.Label(self, text="User ID:", fg="white", bg="black", font=("Helvetica", 12)).pack(pady=(10, 0))
        self.entry = tk.Entry(self, font=("Helvetica", 12), bg="gray15", fg="white", insertbackground="white")
        self.entry.pack(pady=5)
        self.entry.focus()
        enhanced_entry(self.entry, placeholder="I.e. 1234567890123456")

        self.status = tk.Label(self, text="", fg="gray", bg="black", font=("Helvetica", 10))
        self.status.pack(pady=(5, 0))

        tk.Button(
            self,
            text="Add",
            command=self.add_contact,
            bg="gray25",
            fg="white",
            relief="flat",
            font=("Helvetica", 12)
        ).pack(pady=10)


        self.bind("<Return>", lambda e: self.add_contact())
        self.transient(master)
        self.grab_set()

    def add_contact(self):
        contact_id = self.entry.get().strip()
        """if not (contact_id.isdigit() and len(contact_id) == 16):
            self.status.config(text="Invalid User ID", fg="red")
            return
        """

        if contact_id == self.master.user_data["user_id"]:
            self.status.config(text="You cannot add yourself", fg="red")
            return
            
        try:
            # if not check_if_contact_exists(self.master.user_data, self.master.user_data_lock, contact_id):
            #    logger.error("[BUG] This should never execute, because the server should return a 40X error code and that should cause an exception..")
            #    return

            save_contact(self.master.user_data, self.master.user_data_lock, contact_id)
            save_account_data(self.master.user_data, self.master.user_data_lock)
        except ValueError as e:
            self.status.config(text=e, fg="red")
            logger.error("Error occured while adding new contact (%s): %s ", contact_id, e)
            return
            

        self.master.new_contact(contact_id)
        self.destroy()
        messagebox.showinfo("Added", "Added the user to your contact list")

