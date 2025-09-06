from ui.utils import (
        enhanced_entry
)
from ui.password_window import PasswordWindow
from logic.storage import save_account_data
from logic.authentication import authenticate_account
from core.requests import socks_monkey_patch, http_monkey_patch, undo_monkey_patching
from logic.user import build_initial_user_data
from core.crypto import generate_sign_keys
from urllib.parse import urlparse
import tkinter as tk
import logging
import json


logger = logging.getLogger(__name__)

class ServerConnectWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.protocol("WM_DELETE_WINDOW", self.master.destroy)

        self.title("Coldwire – Connect to a Server")
        self.configure(bg="black")
        self.resizable(False, False)

        self.label = tk.Label(self, text="Enter server URL:", fg="white", bg="black")
        self.label.pack(pady=(20, 5))

        self.server_url = tk.Entry(self, bg="gray15", fg="white", insertbackground="white", width=40)
        self.server_url.pack(pady=5)
        self.server_url.focus()
        self.server_url.bind("<Return>", self.on_connect)

        enhanced_entry(self.server_url, placeholder="I.e. example.com ...")
        
        self.use_proxy_var = tk.IntVar()
        self.proxy_check = tk.Checkbutton(
            self,
            text="Use Proxy",
            variable=self.use_proxy_var,
            bg="black",
            fg="white",
            activebackground="black",
            activeforeground="white",
            command=self.toggle_proxy_fields,
            selectcolor="black"
        )
        self.proxy_check.pack(pady=(10, 0), anchor="center")

        self.proxy_fields_frame = tk.Frame(self, bg="black")

        self.proxy_row = tk.Frame(self.proxy_fields_frame, bg="black")

        self.proxy_type_var = tk.StringVar(value="HTTP")
        self.proxy_type_var.trace_add("write", self.update_auth_visibility)

        self.proxy_type_menu = tk.OptionMenu(self.proxy_row, self.proxy_type_var, "HTTP", "SOCKS4", "SOCKS5")
        self.proxy_type_menu.config(bg="gray15", fg="white", highlightthickness=0, width=7)
        self.proxy_type_menu.pack(side="left", padx=(0, 5))

        self.proxy_addr_entry = tk.Entry(
            self.proxy_row, bg="gray15", fg="white", insertbackground="white", width=25
        )
        self.proxy_addr_entry.insert(0, "127.0.0.1:9050")
        self.proxy_addr_entry.pack(side="left")

        self.proxy_row.pack(pady=5)

        self.auth_frame = tk.Frame(self.proxy_fields_frame, bg="black")

        self.proxy_user_entry = tk.Entry(
            self.auth_frame, bg="gray15", fg="white", insertbackground="white", width=18
        )
        self.proxy_user_entry.pack(side="left", padx=(0, 5))

        self.proxy_pass_entry = tk.Entry(
            self.auth_frame, bg="gray15", fg="white", insertbackground="white", width=18, show="*"
        )
        self.proxy_pass_entry.pack(side="left")

        self.auth_frame.pack(pady=5)

        self.proxy_fields_frame.pack_forget()

        self.status_label = tk.Label(self, text="", fg="red", bg="black")
        self.status_label.pack(pady=5)

        self.connect_button = tk.Button(self, text="Connect", command=self.on_connect, bg="gray25", fg="white")
        self.connect_button.pack(pady=10)

        # Shrink to fit default, autosize.
        self.update_idletasks()
        self.geometry("")

    def toggle_proxy_fields(self):
        if self.use_proxy_var.get():
            self.proxy_fields_frame.pack(pady=5)
            self.update_auth_visibility()
        else:
            self.proxy_fields_frame.pack_forget()

        self.update_idletasks()
        self.geometry("")  # Resize again

    def update_auth_visibility(self, *args):
        proxy_type = self.proxy_type_var.get()
        if proxy_type in ["HTTP", "SOCKS5"]:
            self.auth_frame.pack(pady=5)
        else:
            self.auth_frame.pack_forget()

        self.update_idletasks()
        self.geometry("")


    def password_callback(self, password):
        # We save the password (if any) in the user data tmp dict for ease of access across codebase (i.e. saving) 
        self.user_data = build_initial_user_data()
        self.user_data["server_url"] = self.server_url_fixed
        self.user_data["tmp"]["password"] = password

        proxy_info = self.get_proxy_info()
        if proxy_info:
            self.user_data["settings"]["proxy_info"] = proxy_info

        private_key, public_key = generate_sign_keys()

        # lt = long-term
        # These keys are only used to authenticate with the server and to sign ephemeral keys hashes.
        self.user_data["lt_auth_sign_keys"] = {
                "private_key": private_key,
                "public_key": public_key
            }

        self.connect_to_server()

    def connect_to_server(self):
        if self.user_data["settings"]["proxy_info"]:
            if self.user_data["settings"]["proxy_info"]["type"] in ["SOCKS5", "SOCKS4"]:
                try:
                    import socks
                except ImportError:
                    logger.error("SOCKS proxy set and we could not find PySocks. WARNING before you install PySocks: PySocks is largely unmaintained. It's highly recommended you use proxychains instead")
                    self.status_label.config(text="You need to install PySocks to enable SOCKS proxy support!")
                    return

                socks_monkey_patch(self.user_data["settings"]["proxy_info"])
            else:
                http_monkey_patch(self.user_data["settings"]["proxy_info"])
        else:
            undo_monkey_patching()


        try:
            self.user_data = authenticate_account(self.user_data)
        except ValueError as e:
            self.status_label.config(text=e)
            return

        save_account_data(self.user_data, self.master.user_data_lock)
        self.destroy()
        self.master.ready_to_authenticate_callback(self.user_data["tmp"]["password"], already_authenticated = True)


    def get_proxy_info(self):
        proxy_info = None
        if self.use_proxy_var.get():
            proxy_type = self.proxy_type_var.get()
            proxy_addr = self.proxy_addr_entry.get().strip() 
            username = self.proxy_user_entry.get().strip()
            password = self.proxy_pass_entry.get().strip()

            if not proxy_addr or ':' not in proxy_addr:
                self.status_label.config(text="Invalid proxy address.")
                return
            host, port = proxy_addr.split(':', 1)

            try:
                port = int(port)
            except ValueError:
                self.status_label.config(text="Invalid proxy address port!")
                return

            proxy_info = {
                "type": proxy_type,
                "host": host,
                "port": port,
                "username": username,
                "password": password
            }

        if proxy_info:
            logger.info("Using proxy: %s", json.dumps(proxy_info, indent=2))
            return proxy_info
        
        logger.debug("No proxy was set")

        return None

    def clean_server_url(self, url) -> str:
        # hacky mess, but should be fine as its only for ux.

        if (not '.' in url) and not url.startswith("localhost"):
            raise Exception()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url 

        parsed = urlparse(url)

        return f"{parsed.scheme}://{parsed.netloc}"

    def on_connect(self, event=None):
        self.server_url_fixed = self.server_url.get().strip()
        if not self.server_url_fixed:
            self.status_label.config(text="Server address required.")
            return

        try:
            self.server_url_fixed = self.clean_server_url(self.server_url_fixed)
        except Exception:
            self.status_label.config(text="Server address is invalid!")
            return

        if not hasattr(self, "user_data"):
            PasswordWindow(self, self.password_callback)
        else:
            self.status_label.config(text="")
            self.password_callback(self.user_data["tmp"]["password"])
