import asyncio
import threading
import json
from datetime import datetime
from pathlib import Path
import customtkinter as ctk
from tkinter import messagebox
from utils import *
import alice, bob
from utils import GUI_QUEUES, GUI_APP

# Key verification

def init_and_verify_keys(self):
    ensure_ed25519_keys(ALICE_PRIV, ALICE_PUB)
    ensure_ed25519_keys(BOB_PRIV, BOB_PUB)

    alice_fp = fingerprint_pubkey(Path(ALICE_PUB).read_bytes())
    bob_fp = fingerprint_pubkey(Path(BOB_PUB).read_bytes())

    messagebox.showinfo(
        "Fingerprint verification",
        f"Alice fingerprint:\n{alice_fp}\n\nBob fingerprint:\n{bob_fp}\n\n Keys Verified"
    )
    self.clear_chat()
    self.append_message("System", "Welcome! Select a user and start a chat")
    self.disable_chat()

# User config

USER_CONFIGS = {
    "Alice": {
        "STATE_PATH": STATE_ALICE,
        "MY_PRIV": ALICE_PRIV,
        "MY_PUB": ALICE_PUB,
        "THEIR_PUB": BOB_PUB,
        "PORT": SERVER_PORT,
        "HOST": SERVER_HOST,
        "IS_SERVER": True,
        "HISTORY_FILE": "history_alice.json"
    },
    "Bob": {
        "STATE_PATH": STATE_BOB,
        "MY_PRIV": BOB_PRIV,
        "MY_PUB": BOB_PUB,
        "THEIR_PUB": ALICE_PUB,
        "PORT": SERVER_PORT,
        "HOST": SERVER_HOST,
        "IS_SERVER": False,
        "HISTORY_FILE": "history_bob.json"
    },
}

# App

class SecureMessenger(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Secure Messenger")
        self.geometry("950x600")
        self.current_user = None
        self.config = None
        self.reader = None
        self.writer = None
        self.dr = None
        self.chat_ui_enabled = False
        self.messages = {"Alice": [], "Bob": []}
        self.unread = {"Alice": False, "Bob": False}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.create_ui()

    # UI

    def create_ui(self):
        self.sidebar = ctk.CTkFrame(self, width=220)
        self.sidebar.grid(row=0, column=0, sticky="nswe", padx=(10, 0), pady=(10, 10))
        self.sidebar.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(self.sidebar, text="🔐 Secure Messenger", font=ctk.CTkFont(size=18, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(20, 10)
        )

        # Alice button with indicator
        self.alice_frame = ctk.CTkFrame(self.sidebar)
        self.alice_frame.grid(row=1, column=0, padx=20, pady=(10,5), sticky="ew")
        self.alice_button = ctk.CTkButton(self.alice_frame, text="Sign as Alice", command=lambda: self.sign_in("Alice"))
        self.alice_button.pack(side="left", expand=True, fill="x")
        self.alice_msg_indicator = ctk.CTkLabel(self.alice_frame, text="M", fg_color="green", width=24, height=24,
                                                corner_radius=12, text_color="white")
        self.alice_msg_indicator.pack(side="right", padx=5)
        self.alice_msg_indicator.pack_forget()

        # Bob button with indicator
        self.bob_frame = ctk.CTkFrame(self.sidebar)
        self.bob_frame.grid(row=2, column=0, padx=20, pady=(5,10), sticky="ew")
        self.bob_button = ctk.CTkButton(self.bob_frame, text="Sign as Bob", command=lambda: self.sign_in("Bob"))
        self.bob_button.pack(side="left", expand=True, fill="x")
        self.bob_msg_indicator = ctk.CTkLabel(self.bob_frame, text="M", fg_color="green", width=24, height=24,
                                              corner_radius=12, text_color="white")
        self.bob_msg_indicator.pack(side="right", padx=5)
        self.bob_msg_indicator.pack_forget()

        # Exit
        self.exit_frame = ctk.CTkFrame(self.sidebar)
        self.exit_frame.grid(row=4, column=0, padx=20, pady=(10,12), sticky="ew")
        self.exit_button = ctk.CTkButton(self.exit_frame, text="Exit", fg_color=("tomato","tomato"),
                                         hover_color=("OrangeRed","OrangeRed"), text_color=("white","white"),
                                         command=self.destroy)
        self.exit_button.pack(side="left", expand=True, fill="x")

        # Chat display
        self.chat_frame = ctk.CTkFrame(self)
        self.chat_frame.grid(row=0, column=1, sticky="nswe", padx=10, pady=10)
        self.chat_frame.grid_columnconfigure(0, weight=1)
        self.chat_frame.grid_rowconfigure(0, weight=1)
        self.chat_display = ctk.CTkTextbox(self.chat_frame, wrap="word", state="disabled")
        self.chat_display.grid(row=0, column=0, padx=10, pady=(10,10), sticky="nsew")
        self.log("Welcome! Please sign in as Alice or Bob to start")

    # Highlight active user

    def highlight_active_user(self, user):
        active_color = "#00CFCF"
        default_color = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
        self.alice_button.configure(fg_color=default_color)
        self.bob_button.configure(fg_color=default_color)
        if user == "Alice":
            self.alice_button.configure(fg_color=active_color)
        else:
            self.bob_button.configure(fg_color=active_color)

    # Sign in

    def sign_in(self, username):
        self.current_user = username
        self.config = USER_CONFIGS[username]
        self.dr = DoubleRatchet()
        self.log(f"You signed in as {username}.")
        self.log("Preparing secure connection...")
        threading.Thread(target=self.run_asyncio_loop, daemon=True).start()

    def run_asyncio_loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.init_connection())
        loop.close()

    async def init_connection(self):
        ensure_ed25519_keys(self.config["MY_PRIV"], self.config["MY_PUB"])
        ensure_ed25519_keys(self.config["THEIR_PUB"], self.config["THEIR_PUB"])

        my_fp = fingerprint_pubkey(Path(self.config["MY_PUB"]).read_bytes())
        their_fp = fingerprint_pubkey(Path(self.config["THEIR_PUB"]).read_bytes())
        ok = messagebox.askyesno("Fingerprint Verification",
                                 f"{self.current_user} fingerprint:\n{my_fp}\n\nTheir fingerprint:\n{their_fp}\n\nConfirm?")
        if not ok:
            self.log("Fingerprints not confirmed.")
            return

        if self.config["IS_SERVER"]:
            self.log("Waiting for Bob to connect...")
            server = await asyncio.start_server(self.server_handler, self.config["HOST"], self.config["PORT"])
            async with server:
                await server.serve_forever()
        else:
            for attempt in range(10):
                try:
                    self.reader, self.writer = await asyncio.open_connection(self.config["HOST"], self.config["PORT"])
                    break
                except Exception:
                    await asyncio.sleep(1)
            if not self.writer:
                self.log("Could not connect to Alice.")
                return
            self.log("Connected to Alice")
            await self.enable_chat_ui(is_initiator=True)

    async def server_handler(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.log("Bob connected")
        init_and_verify_keys(self)
        await self.enable_chat_ui(is_initiator=False)

    # UI

    async def enable_chat_ui(self, is_initiator: bool):
        if self.chat_ui_enabled:
            return
        self.chat_ui_enabled = True

        self.alice_button.configure(text="Alice 👩", command=lambda: self.switch_user("Alice"))
        self.bob_button.configure(text="Bob 🧑", command=lambda: self.switch_user("Bob"))

        self.entry_frame = ctk.CTkFrame(self.chat_frame)
        self.entry_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0,10))
        self.entry_frame.grid_columnconfigure(0, weight=1)
        self.entry = ctk.CTkEntry(self.entry_frame, placeholder_text="Enter message...")
        self.entry.grid(row=0, column=0, sticky="ew", padx=(0,10))
        self.entry.bind("<Return>", self.send_message)
        self.send_button = ctk.CTkButton(self.entry_frame, text="Send", command=self.send_message)
        self.send_button.grid(row=0, column=1)
        self.log("Both sides authenticated. Chat interface activated.")

    # Chat functions

    def enable_chat(self):
        self.entry.configure(state="normal")
        self.send_button.configure(state="normal")

    def disable_chat(self):
        self.entry.configure(state="disabled")
        self.send_button.configure(state="disabled")

    def clear_chat(self):
        self.chat_display.configure(state="normal")
        self.chat_display.delete("1.0", "end")
        self.chat_display.configure(state="disabled")

    def switch_user(self, user):
        self.current_user = user
        self.display_messages(user)
        self.clear_indicator(user)
        self.append_message("System", f"Current user switched to {user}")
        self.enable_chat()
        self.highlight_active_user(user)

    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, "end")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.messages[self.current_user].append(("me", msg, timestamp))
        self.append_message(self.current_user, msg, timestamp)

        peer = "Bob" if self.current_user == "Alice" else "Alice"
        self.messages[peer].append(("peer", msg, timestamp))
        self.show_indicator(peer)

    def append_message(self, sender, msg_text, timestamp=None):
        self.chat_display.configure(state="normal")
        if timestamp is None:
            timestamp = datetime.now().strftime("%H:%M:%S")
        if sender == "Alice":
            prefix, tag, color = "👩 Alice: ", "alice_msg", "#008000"
        elif sender == "Bob":
            prefix, tag, color = "🧑 Bob: ", "bob_msg", "#0078FF"
        else:
            prefix, tag, color = "🛈 ", "system_msg", "#999999"
        self.chat_display.insert("end", f"{prefix}{msg_text} ({timestamp})\n", tag)
        self.chat_display.tag_config(tag, foreground=color)
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

    def display_messages(self, user):
        self.chat_display.configure(state="normal")
        self.chat_display.delete("1.0", "end")
        for sender_type, msg, timestamp in self.messages[user]:
            sender = user if sender_type == "me" else ("Bob" if user == "Alice" else "Alice")
            self.append_message(sender, msg, timestamp)
        self.chat_display.configure(state="disabled")

    def show_indicator(self, user):
        if user == "Alice":
            self.alice_msg_indicator.pack(side="right", padx=5)
        else:
            self.bob_msg_indicator.pack(side="right", padx=5)

    def clear_indicator(self, user):
        if user == "Alice":
            self.alice_msg_indicator.pack_forget()
        else:
            self.bob_msg_indicator.pack_forget()

    def log(self, text):
        self.chat_display.configure(state="normal")
        now = datetime.now().strftime("%H:%M:%S")
        self.chat_display.insert("end", f"🛈 {text} ({now})\n", "system_msg")
        self.chat_display.tag_config("system_msg", foreground="#999")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

# Main

if __name__ == "__main__":
    ensure_ed25519_keys(ALICE_PRIV, ALICE_PUB)
    ensure_ed25519_keys(BOB_PRIV, BOB_PUB)
    app = SecureMessenger()
    app.mainloop()
