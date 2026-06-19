# chat_gui.py
# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# chat_gui.py
import tkinter as tk
from tkinter import filedialog
import queue
import re
import time
import secrets
import json
import os
import socket
import ssl
import threading
import customtkinter as ctk
from src.client.chat_client import ChatClient, flash_taskbar
from src.common.crypto_utils import (
    IdentityKeyManager,
    FingerprintWords,
)
from src.common.padding import PaddedSender, PaddedReceiver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None
    Image = None
    ImageDraw = None


# ----------------------------------------------------------------------
CONFIG_PATH = "local_keys/client_config.json"

DEFAULT_CLIENT_CONFIG = {
    "server": {"host": "127.0.0.1", "port": 5555, "auto_connect": False},
    "window": {"width": 1100, "height": 760, "x": None, "y": None},
    "theme": "dark",
}


class ChatGUI:
    """Graphical User Interface - Modern QQ-like Layout"""
    USER_LIST_REFRESH_MS = 5000

    # ------------------------------------------------------------------
    # Config helpers
    def _load_client_config(self):
        """Load client_config.json; create default on first run."""
        if not os.path.exists("local_keys"):
            os.makedirs("local_keys")
        if not os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CLIENT_CONFIG, f, indent=2, ensure_ascii=False)
            return dict(DEFAULT_CLIENT_CONFIG)
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            # Shallow merge: fill missing top-level keys
            for k, v in DEFAULT_CLIENT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
            return cfg
        except Exception:
            return dict(DEFAULT_CLIENT_CONFIG)

    def _save_client_config(self, **overrides):
        """Save config atomically. Pass keyword overrides to update in-memory cfg before writing."""
        cfg = getattr(self, '_client_config', dict(DEFAULT_CLIENT_CONFIG))
        for k, v in overrides.items():
            if isinstance(v, dict):
                cfg.setdefault(k, {}).update(v)
            else:
                cfg[k] = v
        self._client_config = cfg
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CONFIG_PATH)

    # ------------------------------------------------------------------

    def __init__(self):
        cfg = self._load_client_config()
        self._client_config = cfg

        ctk.set_appearance_mode(cfg.get("theme", "dark"))
        ctk.set_default_color_theme("dark-blue")
        self.root = ctk.CTk()
        default_font = ('Segoe UI', 10)
        self.root.option_add('*Font', default_font)
        self.root.option_add('*Dialog.msg.Font', default_font)
        self.root.title("KaleidoTalk V3.0")

        # Window size & position
        win = cfg.get("window", {})
        w = win.get("width", 1100) or 1100
        h = win.get("height", 760) or 760
        x = win.get("x")
        y = win.get("y")
        if x is not None and y is not None:
            self.root.geometry(f"{w}x{h}+{int(x)}+{int(y)}")
        else:
            screen_w = self.root.winfo_screenwidth()
            screen_h = self.root.winfo_screenheight()
            w = min(1180, max(960, screen_w - 120))
            h = min(820, max(700, screen_h - 120))
            self.root.geometry(f"{w}x{h}")
        self.root.minsize(960, 700)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind("<Unmap>", self.on_window_unmap)

        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()

        # Responsive spacing: scale all paddings based on screen resolution
        # Reference: 1080p (1920x1080). Scale factor = min(w/1920, h/1080), clamped [0.7, 1.3]
        self._scale = max(0.7, min(1.3, min(screen_w / 1920, screen_h / 1080)))
        s = self._scale  # shorthand

        # Computed spacing values
        self._pad = {
            'main_x':     max(4, int(10 * s)),   # main frame horizontal padding
            'main_y':     0,                     # main frame vertical padding
            'toolbar_h':  max(32, int(38 * s)),   # toolbar height
            'tb_padx':    max(4, int(6 * s)),     # toolbar label spacing
            'tb_btn_w':   max(68, int(82 * s)),   # toolbar button width
            'tb_btn_h':   max(26, int(30 * s)),   # toolbar button height
            'tb_btn_fs':  max(11, int(12 * s)),   # toolbar button font size
            'tb_fs':      max(11, int(12 * s)),   # toolbar label font size
            'content_gap':max(2, int(6 * s)),     # gap between left panel and right panel
            'header_h':   max(42, int(48 * s)),   # chat/user-list header height
            'header_fs':  max(11, int(13 * s)),   # header font size
            'header_pad': max(8, int(12 * s)),    # header padding
            'msg_padx':   max(4, int(8 * s)),     # message area horizontal padding
            'msg_pady':   max(2, int(3 * s)),     # message bubble vertical gap
            'bubble_pad': max(6, int(10 * s)),    # bubble internal padding
            'bubble_cr':  max(12, int(16 * s)),   # bubble corner radius
            'avatar_sz':  max(30, int(36 * s)),   # avatar circle size
            'avatar_fs':  max(10, int(12 * s)),   # avatar font size
            'msg_fs':     max(10, int(12 * s)),   # message text font size
            'time_fs':    max(8, int(9 * s)),     # timestamp font size
            'time_pad':   max(2, int(4 * s)),     # timestamp top padding
            'send_padx':  max(8, int(12 * s)),    # send area horizontal padding
            'send_pady':  max(6, int(10 * s)),    # send area vertical padding
            'entry_h':    max(36, int(42 * s)),   # message entry height
            'send_btn_w': max(72, int(92 * s)),   # send button width
            'send_fs':    max(10, int(12 * s)),   # send button font size
            'left_w':     max(240, int(280 * s)), # left panel width
            'list_row_h': max(46, int(54 * s)),   # user list row height
            'list_fs':    max(10, int(12 * s)),   # user list name font size
            'spacer_w':   max(30, int(50 * s)),   # message side spacer width
        }

        self.message_queue = queue.Queue()
        self.client = ChatClient()
        self.client.callback = self.on_message_received
        self.client.cert_verify_callback = self._cert_verify_dialog

        # Apply saved server address
        srv = cfg.get("server", {})
        self.client.host = srv.get("host", "127.0.0.1")
        self.client.port = srv.get("port", 5555)

        self._pending_register = None

        self.is_minimized_to_tray = False
        self._tray_minimize_pending = False
        self.tray_icon = None
        self.is_exiting = False
        self._context_menu = None
        self._context_menu_user = None
        self._displayed_users = []
        self._user_rows = {}
        self._user_unread = {}  # username -> unread count
        self._pending_add_user = None  # username waiting for pubkey verification
        self.selected_user = None

        # Message storage: username -> list of (is_self, message, timestamp)
        self._messages = {}

        self._color_palette = [
            '#1f77b4',
            '#2ca02c',
            '#d62728',
            '#9467bd',
            '#ff7f0e',
            '#17becf',
            '#8c564b',
        ]
        self._name_colors = {}

        self.setup_ui()
        self.root.after(100, self.process_messages)
        self.root.after(self.USER_LIST_REFRESH_MS, self.refresh_online_users)
        if cfg.get("server", {}).get("auto_connect", False):
            self.root.after(500, self._auto_connect)
        else:
            self.root.after(300, self.connect_to_server)

    # ------------------------------------------------------------------
    # UI Setup - Modern QQ-like Layout
    def setup_ui(self):
        main_frame = ctk.CTkFrame(self.root, corner_radius=0)
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=0)
        main_frame.rowconfigure(1, weight=1)

        # Top Toolbar - Compact
        p = self._pad
        toolbar = ctk.CTkFrame(main_frame, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=p['main_x'], pady=0)

        self.status_label = ctk.CTkLabel(toolbar, text="Not Connected", text_color="#ff6b6b", font=("Segoe UI", p['tb_fs'], "bold"))
        self.status_label.pack(side=tk.LEFT, padx=(0, p['tb_padx']), pady=0)

        self.user_label = ctk.CTkLabel(toolbar, text="Not Logged In", font=("Segoe UI", p['tb_fs']))
        self.user_label.pack(side=tk.LEFT, padx=(0, p['tb_padx']), pady=0)
        self.user_label.bind("<Button-1>", self._on_user_label_click)

        self.crypto_label = ctk.CTkLabel(toolbar, text="🔓 No Encryption", text_color="#ff6b6b", font=("Segoe UI", p['tb_fs']))
        self.crypto_label.pack(side=tk.LEFT, padx=(0, p['tb_padx']), pady=0)

        self.connect_btn = ctk.CTkButton(toolbar, text="Connect", command=self.connect_to_server, corner_radius=6, width=p['tb_btn_w'], height=p['tb_btn_h'], font=("Segoe UI", p['tb_btn_fs']))
        self.connect_btn.pack(side=tk.LEFT, padx=(p['tb_padx'], 0), pady=0)

        self.register_btn = ctk.CTkButton(toolbar, text="Register", command=self.register_user, state=tk.DISABLED, corner_radius=6, width=p['tb_btn_w'], height=p['tb_btn_h'], font=("Segoe UI", p['tb_btn_fs']))
        self.register_btn.pack(side=tk.LEFT, padx=0, pady=0)

        self.login_btn = ctk.CTkButton(toolbar, text="Login", command=self.login_user, state=tk.DISABLED, corner_radius=6, width=max(40, p['tb_btn_w'] - 8), height=p['tb_btn_h'], font=("Segoe UI", p['tb_btn_fs']))
        self.login_btn.pack(side=tk.LEFT, padx=0, pady=0)

        self.logout_btn = ctk.CTkButton(toolbar, text="Logout", command=self.logout_user, state=tk.DISABLED, corner_radius=6, width=max(40, p['tb_btn_w'] - 8), height=p['tb_btn_h'], font=("Segoe UI", p['tb_btn_fs']))
        self.logout_btn.pack(side=tk.LEFT, padx=0, pady=0)

        self.about_btn = ctk.CTkButton(toolbar, text="About", command=self.show_about, corner_radius=6, width=max(40, p['tb_btn_w'] - 8), height=p['tb_btn_h'], font=("Segoe UI", p['tb_btn_fs']))
        self.about_btn.pack(side=tk.LEFT, padx=0, pady=0)

        # Notification label (right side of toolbar, for non-critical status messages)
        self._notify_label = ctk.CTkLabel(toolbar, text="", font=("Segoe UI", p['tb_fs']), text_color=("#888888", "#aaaaaa"), anchor="e")
        self._notify_label.pack(side=tk.RIGHT, padx=(p['tb_padx'], 0), pady=0)
        self._notify_timer = None

        # Main Content Area - Split: Left User List + Right Chat
        content_frame = ctk.CTkFrame(main_frame, corner_radius=0, fg_color="transparent")
        content_frame.grid(row=1, column=0, sticky="nsew", padx=p['main_x'], pady=0)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(0, weight=1)

        # ---- Left Panel: User List ----
        left_panel = ctk.CTkFrame(content_frame, corner_radius=12, width=p['left_w'])
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, p['content_gap']))
        left_panel.grid_propagate(False)
        left_panel.columnconfigure(0, weight=1)
        left_panel.rowconfigure(1, weight=1)

        # User list header
        list_header = ctk.CTkFrame(left_panel, fg_color="transparent", height=p['header_h'])
        list_header.grid(row=0, column=0, sticky="ew", padx=p['header_pad'], pady=(p['header_pad'], max(2, p['header_pad'] // 2)))
        list_header.grid_propagate(False)
        list_header.columnconfigure(0, weight=1)

        ctk.CTkLabel(list_header, text="Contacts", font=("Segoe UI", p['header_fs'], "bold")).grid(row=0, column=0, sticky="w")

        # Add new user button (+)
        add_sz = max(20, int(p['header_h'] * 0.65))
        self.add_user_btn = ctk.CTkButton(
            list_header, text="+", font=("Segoe UI", max(12, int(p['header_fs'] * 1.2)), "bold"),
            width=add_sz, height=add_sz, corner_radius=add_sz // 2,
            command=self._on_add_user_click,
            fg_color=("#e0e0e0", "#3a3a3a"),
            hover_color=("#d0d0d0", "#4a4a4a"),
            text_color=("#333333", "#ffffff")
        )
        self.add_user_btn.grid(row=0, column=1, sticky="e")

        # Scrollable user list
        self.users_list_frame = ctk.CTkScrollableFrame(left_panel, corner_radius=8, fg_color="transparent")
        self.users_list_frame.grid(row=1, column=0, sticky="nsew", padx=max(4, p['header_pad'] // 2), pady=(0, max(4, p['header_pad'] // 2)))
        self.users_list_frame.columnconfigure(0, weight=1)

        # ---- Right Panel: Chat Area ----
        right_panel = ctk.CTkFrame(content_frame, corner_radius=12)
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.columnconfigure(0, weight=1)
        right_panel.rowconfigure(1, weight=1)
        right_panel.rowconfigure(2, weight=0)

        # Chat header - shows current chat partner
        self.chat_header = ctk.CTkFrame(right_panel, fg_color="transparent", height=p['header_h'])
        self.chat_header.grid(row=0, column=0, sticky="ew", padx=p['header_pad'], pady=(p['header_pad'], max(2, p['header_pad'] // 2)))
        self.chat_header.grid_propagate(False)

        self.chat_header_label = ctk.CTkLabel(
            self.chat_header, text="Select a user to start chatting",
            font=("Segoe UI", p['header_fs'], "bold"), text_color=("#666666", "#aaaaaa")
        )
        self.chat_header_label.pack(side=tk.LEFT)

        # Messages canvas area (bubble chat)
        self.messages_canvas = tk.Canvas(right_panel, highlightthickness=0, bg="#1a1a2e")
        self.messages_canvas.grid(row=1, column=0, sticky="nsew", padx=p['msg_padx'], pady=max(2, p['msg_pady']))
        self.messages_canvas.columnconfigure(0, weight=1)

        # Scrollbar for messages
        self.messages_scrollbar = ctk.CTkScrollbar(right_panel, command=self.messages_canvas.yview)
        self.messages_scrollbar.grid(row=1, column=1, sticky="ns", pady=max(2, p['msg_pady']))
        self.messages_canvas.configure(yscrollcommand=self.messages_scrollbar.set)

        # Messages inner frame
        self.messages_frame = ctk.CTkFrame(self.messages_canvas, fg_color="transparent", corner_radius=0)
        self.messages_canvas_window = self.messages_canvas.create_window((0, 0), window=self.messages_frame, anchor="nw", width=self.messages_canvas.winfo_width())
        self.messages_frame.bind("<Configure>", self._on_messages_frame_configure)
        self.messages_canvas.bind("<Configure>", self._on_canvas_configure)
        self.messages_canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Send Area
        send_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        send_frame.grid(row=2, column=0, sticky="ew", padx=p['send_padx'], pady=(p['send_pady'], p['send_pady']))
        send_frame.columnconfigure(0, weight=1)

        self.message_entry = ctk.CTkEntry(
            send_frame, corner_radius=20, height=p['entry_h'],
            placeholder_text="Type a message...",
            font=("Segoe UI", p['send_fs']),
            state=tk.DISABLED
        )
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, max(4, p['send_padx'] // 2)))
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        self.send_btn = ctk.CTkButton(
            send_frame, text="Send", command=self.send_message,
            state=tk.DISABLED, corner_radius=20, width=p['send_btn_w'], height=p['entry_h'],
            font=("Segoe UI", p['send_fs'], "bold")
        )
        self.send_btn.grid(row=0, column=1)

        self.update_button_states()

    # ------------------------------------------------------------------
    # Messages Canvas scrolling
    def _on_messages_frame_configure(self, event=None):
        self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))

    def _on_canvas_configure(self, event=None):
        self.messages_canvas.itemconfig(self.messages_canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        self.messages_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _scroll_to_bottom(self):
        self.messages_canvas.update_idletasks()
        self.messages_canvas.yview_moveto(1.0)

    # ------------------------------------------------------------------
    # Button States
    def update_button_states(self):
        if self.client and self.client.sock:
            self.connect_btn.configure(state=tk.DISABLED)
            if self.client.server_ed25519_pub:
                self.register_btn.configure(state=tk.NORMAL)
                self.login_btn.configure(state=tk.NORMAL)
            else:
                self.register_btn.configure(state=tk.DISABLED)
                self.login_btn.configure(state=tk.DISABLED)

            if self.client.session_id and self.client.session_key:
                self.logout_btn.configure(state=tk.NORMAL)
                self.send_btn.configure(state=tk.NORMAL)
                self.message_entry.configure(state=tk.NORMAL)
                self.user_label.configure(text=f"User: {self.client.username}")
                self.crypto_label.configure(text="🔐 End-to-End Encrypted", text_color="#6ee7b7")
            else:
                self.logout_btn.configure(state=tk.DISABLED)
                self.send_btn.configure(state=tk.DISABLED)
                self.message_entry.configure(state=tk.DISABLED)
                self.user_label.configure(text="Not Logged In")
                self.crypto_label.configure(text="🔓 Unencrypted", text_color="#ff6b6b")
        else:
            self.connect_btn.configure(state=tk.NORMAL)
            self.register_btn.configure(state=tk.DISABLED)
            self.login_btn.configure(state=tk.DISABLED)
            self.logout_btn.configure(state=tk.DISABLED)
            self.send_btn.configure(state=tk.DISABLED)
            self.message_entry.configure(state=tk.DISABLED)
            self.status_label.configure(text="Not Connected", text_color="#ff6b6b")
            self.user_label.configure(text="Not Logged In")
            self.crypto_label.configure(text="🔓 Unencrypted", text_color="#ff6b6b")

    # ------------------------------------------------------------------
    # Dialog helpers
    def _dialog_input(self, title, prompt, show=None, initial=''):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("420x190")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=prompt, wraplength=350).pack(pady=(20, 10), padx=20)
        var = tk.StringVar(value=initial)
        entry = ctk.CTkEntry(dlg, textvariable=var, width=280, show=show, corner_radius=6)
        entry.pack(pady=(0, 10))
        entry.focus_set()
        result = None

        def on_ok():
            nonlocal result
            result = var.get()
            dlg.destroy()

        def on_cancel():
            dlg.destroy()

        entry.bind('<Return>', lambda e: on_ok())
        entry.bind('<Escape>', lambda e: on_cancel())
        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack()
        ctk.CTkButton(btn_frame, text="OK", command=on_ok, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="Cancel", command=on_cancel, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)

        self.center_dialog(dlg)
        dlg.update_idletasks()
        entry.focus_force()
        self.root.wait_window(dlg)
        return result

    def _dialog_choice(self, title, message, choices):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("560x300")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=message, justify=tk.LEFT, wraplength=450).pack(pady=(20, 10), padx=20)
        sel_var = tk.IntVar(value=-1)
        list_frame = ctk.CTkScrollableFrame(dlg, width=450, height=120, corner_radius=6)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20)

        for idx, (text, val) in enumerate(choices):
            row = ctk.CTkFrame(list_frame, fg_color="transparent")
            row.pack(fill=tk.X, pady=4)
            rb = ctk.CTkRadioButton(row, text="", variable=sel_var, value=idx)
            rb.pack(side=tk.LEFT)
            lbl = ctk.CTkLabel(row, text=text, wraplength=420, justify=tk.LEFT)
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6,0))
            if idx == 0:
                first_rb = rb

        result = [None]

        def on_ok():
            idx = sel_var.get()
            if idx is None or idx < 0 or idx >= len(choices):
                result[0] = None
            else:
                result[0] = choices[idx][1]
            dlg.destroy()

        def on_cancel():
            result[0] = None
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=8)
        ctk.CTkButton(btn_frame, text="OK", command=on_ok, width=110, corner_radius=8).pack(side=tk.LEFT, padx=6)
        ctk.CTkButton(btn_frame, text="Cancel", command=on_cancel, width=110, corner_radius=8).pack(side=tk.LEFT, padx=6)

        dlg.bind('<Escape>', lambda e: on_cancel())
        self.center_dialog(dlg)
        dlg.update_idletasks()
        if 'first_rb' in locals():
            first_rb.focus_force()
        self.root.wait_window(dlg)
        return result[0]

    def _dialog_showinfo(self, title, message):
        self._dialog_message(title, message)

    def _dialog_showerror(self, title, message):
        self._dialog_message(title, message)

    def _dialog_message(self, title, message):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("560x320")
        dlg.resizable(True, True)

        content_frame = ctk.CTkScrollableFrame(dlg, corner_radius=6)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(20, 12))
        ctk.CTkLabel(content_frame, text=message, justify=tk.LEFT, wraplength=500).pack(anchor="w", fill=tk.BOTH, expand=True)

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=(0, 14))
        ctk.CTkButton(btn_frame, text="OK", command=dlg.destroy, width=100, corner_radius=8).pack()

        dlg.bind('<Escape>', lambda e: dlg.destroy())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)

    # ------------------------------------------------------------------
    # TLS Certificate BIP39 Confirmation Dialog
    def _cert_verify_dialog(self, endpoint, fingerprint):
        words = FingerprintWords.fingerprint_to_words(fingerprint, 6)
        words_str = "  ".join(words).upper()

        dlg = ctk.CTkToplevel(self.root)
        dlg.title("TLS Certificate Verification")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("700x430")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=f"First connection to {endpoint}, please verify server TLS certificate fingerprint:", wraplength=600, font=("", 11, "bold")).pack(pady=10)

        word_frame = ctk.CTkFrame(dlg)
        word_frame.pack(pady=15, padx=20, fill=tk.X)
        ctk.CTkLabel(word_frame, text="Fingerprint Words (6):", font=("", 10, "bold")).pack(anchor="w", pady=(0, 8))
        ctk.CTkLabel(word_frame, text=words_str, font=("", 16, "bold"), text_color=("#0066ff", "#6699ff")).pack(anchor="w", pady=10, padx=10)

        ctk.CTkLabel(dlg, text="Verify these words through another secure channel (phone/in person).", wraplength=600, text_color=("orange", "orange"), font=("", 9)).pack(pady=5)

        result = [False]

        def trust():
            result[0] = True
            dlg.destroy()

        def reject():
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=15)
        ctk.CTkButton(btn_frame, text="Trust", command=trust, width=100, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="Reject", command=reject, width=100, corner_radius=8).pack(side=tk.LEFT, padx=5)

        dlg.bind('<Escape>', lambda e: reject())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    # ------------------------------------------------------------------
    def show_about(self):
        about_text = (
            "KaleidoTalk Chat Application\n"
            "Version 3.0\n"
            "Copyright (C) 2026 Bangze Han\n\n"
            "This program is free software: you can redistribute it and/or modify\n"
            "it under the terms of the GNU General Public License as published by\n"
            "the Free Software Foundation, either version 3 of the License, or\n"
            "(at your option) any later version.\n\n"
            "This program is distributed in the hope that it will be useful,\n"
            "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"
            "You should have received a copy of the GNU General Public License\n"
            "along with this program. If not, see <https://www.gnu.org/licenses/>.\n\n"
            "Third-party libraries:\n"
            "- cryptography (Apache 2.0)\n"
            "- pystray (LGPLv3)\n"
            "- PIL (MIT derivative)\n"
            "- CustomTkinker (MIT)\n"
        )
        self._dialog_showinfo("About KaleidoTalk", about_text)

    def center_dialog(self, dialog):
        dialog.update_idletasks()
        req_w = max(dialog.winfo_width(), dialog.winfo_reqwidth())
        req_h = max(dialog.winfo_height(), dialog.winfo_reqheight())
        screen_w = dialog.winfo_screenwidth()
        screen_h = dialog.winfo_screenheight()
        w = min(req_w, max(320, screen_w - 80))
        h = min(req_h, max(180, screen_h - 120))
        x = max(0, (screen_w // 2) - (w // 2))
        y = max(0, (screen_h // 2) - (h // 2))
        dialog.geometry(f'{w}x{h}+{x}+{y}')

    # ------------------------------------------------------------------
    # Connection and Login Flow
    def connect_to_server(self):
        default_addr = f"{self.client.host}:{self.client.port}"
        addr = self._dialog_input("Connect to Server", "Enter Address:Port", initial=default_addr)
        if not addr:
            return
        try:
            host, port = addr.split(':')
            port = int(port)
        except:
            host, port = "127.0.0.1", 5555
        self.client.host = host
        self.client.port = port
        self._do_connect()
        # Save server address
        self._save_client_config(server={"host": host, "port": port})

    def _do_connect(self):
        """Common connection logic: call client.connect() and update UI."""
        self.client.callback = self.on_message_received
        ok = self.client.connect()
        if ok:
            self.status_label.configure(text="Connected (TLS)", text_color="#6ee7b7")
            self.append_system_message("Connected to server (TLS)")
        else:
            self.status_label.configure(text="Connection failed", text_color="#ff6b6b")
            self._dialog_showerror("Error", "Cannot connect to server")
        self.update_button_states()

    def _auto_connect(self):
        """Silent auto-connect based on saved config (no dialog on failure)."""
        server = self._client_config.get("server", {})
        self.client.host = server.get("host", "127.0.0.1")
        self.client.port = server.get("port", 5555)
        self.client.callback = self.on_message_received
        ok = self.client.connect()
        if ok:
            self.status_label.configure(text="Connected (TLS)", text_color="#6ee7b7")
            self.append_system_message("Auto-connected to server (TLS)")
        else:
            self.status_label.configure(text="Disconnected", text_color="#ff6b6b")
        self.update_button_states()

    def register_user(self):
        if not self.client.server_ed25519_pub:
            self._dialog_showerror("Error", "Server public key not ready")
            return
        if self.client.session_id and self.client.session_key:
            self.client.logout()
            self.append_system_message("Current account already logged in; auto-logged out to continue registration")
        username = self._dialog_input("Register", "Username (3-20 alphanumeric):")
        if not username:
            return
        if not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            self._dialog_showerror("Error", "Invalid username format (3-20 alphanumeric characters)")
            return
        pw = self._dialog_input("Register", "Password (at least 8 chars, letters and numbers):", show='*')
        if not pw:
            return
        if len(pw) < 8:
            self._dialog_showerror("Error", "Password must be at least 8 characters")
            return

        choice = self._dialog_choice("Private Key Storage", "Choose private key storage method:",
                                     [("Store on Server (login from any device)", True),
                                      ("Local Storage Only (key never leaves device)", False)])
        if choice is None:
            return

        self._pending_register = {
            'username': username,
            'password': pw,
            'store_private_key': choice,
            'invite_code': '',
        }

        invite = ''
        if self._reg_policy_required():
            invite = self._dialog_input("Invite Code", "Please enter invite code:")
            if not invite:
                self._pending_register = None
                return
            self._pending_register['invite_code'] = invite

        self.client.register(username, pw, store_private_key=choice, invite_code=invite)

    def _reg_policy_required(self):
        return bool(self.client.require_invite_for_register)

    def login_user(self):
        if not self.client.server_ed25519_pub:
            self._dialog_showerror("Error", "Server public key not ready")
            return

        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Login")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("440x320")
        dlg.resizable(False, False)

        ctk.CTkLabel(dlg, text="Username", font=("", 11)).pack(pady=(20, 4), padx=40, anchor="w")
        user_var = tk.StringVar()
        user_entry = ctk.CTkEntry(dlg, textvariable=user_var, width=340, corner_radius=6)
        user_entry.pack(pady=(0, 12), padx=40)
        user_entry.focus_set()

        ctk.CTkLabel(dlg, text="Password", font=("", 11)).pack(pady=(0, 4), padx=40, anchor="w")
        pw_var = tk.StringVar()
        pw_entry = ctk.CTkEntry(dlg, textvariable=pw_var, width=340, show="*", corner_radius=6)
        pw_entry.pack(pady=(0, 16), padx=40)

        result = [None]

        def do_login():
            username = user_var.get().strip()
            if not username:
                return
            pw = pw_var.get()
            if not pw:
                self._dialog_showerror("Error", "Password cannot be empty")
                return
            result[0] = True
            self.client.login(username, pw)
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=(0, 8))
        ctk.CTkButton(btn_frame, text="Login", command=do_login, width=120, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="Cancel", command=dlg.destroy, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)

        pw_entry.bind('<Return>', lambda e: do_login())
        dlg.bind('<Escape>', lambda e: dlg.destroy())

        # Freeze link at bottom
        freeze_btn = ctk.CTkButton(
            dlg, text="Forgot password or account compromised?\nPermanently freeze your account",
            command=lambda: [dlg.destroy(), self._dialog_freeze_account()],
            fg_color="transparent",
            text_color=("#888888", "#777777"),
            font=("", 9, "underline"),
            hover_color=("#e8e8e8", "#333333"),
            width=340,
            corner_radius=6,
        )
        freeze_btn.pack(pady=(6, 12))

        self.center_dialog(dlg)
        dlg.update_idletasks()
        user_entry.focus_force()
        self.root.wait_window(dlg)

    def logout_user(self):
        self.client.logout()
        # Clear all state
        self.selected_user = None
        self._messages.clear()
        self._displayed_users.clear()
        self._user_rows.clear()
        self._user_unread.clear()
        self._name_colors.clear()
        self._update_user_list([])
        self._update_chat_header()
        self._render_messages()
        self._show_notification("Logged out")

    # ------------------------------------------------------------------
    # Message Sending and Display - Bubble Style
    def send_message(self):
        if not self.selected_user:
            return
        msg = self.message_entry.get().strip()
        if not msg:
            return
        if self.client.send_message(self.selected_user, msg):
            # Store message locally
            ts = time.strftime("%H:%M")
            self._add_message(self.selected_user, True, msg, ts)
            self.message_entry.delete(0, tk.END)

    def _add_message(self, username, is_self, message, timestamp=None):
        if timestamp is None:
            timestamp = time.strftime("%H:%M")
        if username not in self._messages:
            self._messages[username] = []
        self._messages[username].append((is_self, message, timestamp))
        if self.selected_user == username:
            self._render_messages()

    def _render_messages(self):
        # Clear existing messages
        for widget in self.messages_frame.winfo_children():
            widget.destroy()

        if not self.selected_user or self.selected_user not in self._messages:
            # Show placeholder
            placeholder = ctk.CTkLabel(
                self.messages_frame,
                text="No messages yet\nStart a conversation!",
                font=("Segoe UI", 12),
                text_color=("#999999", "#666666")
            )
            placeholder.pack(pady=100)
            return

        messages = self._messages.get(self.selected_user, [])
        for is_self, message, timestamp in messages:
            self._create_bubble_message(is_self, message, timestamp)

        self.root.after(50, self._scroll_to_bottom)

    def _create_bubble_message(self, is_self, message, timestamp):
        """Create a bubble message widget — timestamp inside the bubble to eliminate extra spacing"""
        p = self._pad
        # Single row container using tk.Frame (zero native padding, unlike CTkFrame)
        outer = tk.Frame(self.messages_frame, bg="#1a1a2e")
        outer.pack(fill=tk.X, padx=p['msg_padx'], pady=(0, max(1, p['msg_pady'])))

        if is_self:
            outer.columnconfigure(0, weight=1)
            # Invisible spacer
            spacer = tk.Frame(outer, width=p['spacer_w'], bg="#1a1a2e")
            spacer.grid(row=0, column=0, sticky="nsew")

            # Bubble with timestamp inside
            bubble = ctk.CTkFrame(
                outer,
                fg_color=("#0078d4", "#0078d4"),
                corner_radius=p['bubble_cr']
            )
            bubble.grid(row=0, column=1, sticky="e")

            msg_label = ctk.CTkLabel(
                bubble, text=message,
                font=("Segoe UI", p['msg_fs']),
                text_color="white",
                wraplength=400,
                justify=tk.LEFT
            )
            msg_label.pack(padx=p['bubble_pad'], pady=(p['bubble_pad'] // 2, 0))

            time_label = ctk.CTkLabel(
                bubble, text=timestamp,
                font=("Segoe UI", p['time_fs']),
                text_color=("#aaddff", "#88bbdd"),
                anchor="e"
            )
            time_label.pack(fill=tk.X, padx=p['bubble_pad'], pady=(0, max(2, p['bubble_pad'] // 3)))
        else:
            outer.columnconfigure(1, weight=1)

            # Avatar circle with first letter
            avatar = ctk.CTkFrame(
                outer, width=p['avatar_sz'], height=p['avatar_sz'],
                fg_color=self._color_for_name(self.selected_user),
                corner_radius=p['avatar_sz'] // 2
            )
            avatar.grid(row=0, column=0, padx=(0, max(4, p['bubble_pad'] // 2)), sticky="n")
            avatar.grid_propagate(False)

            avatar_label = ctk.CTkLabel(
                avatar, text=self.selected_user[0].upper(),
                font=("Segoe UI", p['avatar_fs'], "bold"),
                text_color="white"
            )
            avatar_label.place(relx=0.5, rely=0.5, anchor="center")

            # Bubble with timestamp inside
            bubble = ctk.CTkFrame(
                outer,
                fg_color=("#f0f0f0", "#2d2d3a"),
                corner_radius=p['bubble_cr']
            )
            bubble.grid(row=0, column=1, sticky="w")

            msg_label = ctk.CTkLabel(
                bubble, text=message,
                font=("Segoe UI", p['msg_fs']),
                text_color=("#333333", "#e0e0e0"),
                wraplength=400,
                justify=tk.LEFT
            )
            msg_label.pack(padx=p['bubble_pad'], pady=(p['bubble_pad'] // 2, 0))

            time_label = ctk.CTkLabel(
                bubble, text=timestamp,
                font=("Segoe UI", p['time_fs']),
                text_color=("#999999", "#777777"),
                anchor="w"
            )
            time_label.pack(fill=tk.X, padx=p['bubble_pad'], pady=(0, max(2, p['bubble_pad'] // 3)))

            spacer = tk.Frame(outer, width=p['spacer_w'], bg="#1a1a2e")
            spacer.grid(row=0, column=2, sticky="nsew")

    def _show_notification(self, message, duration=4000, color=None):
        """Show a temporary notification in the toolbar label"""
        if color:
            self._notify_label.configure(text=message, text_color=color)
        else:
            self._notify_label.configure(text=message, text_color=("#cccccc", "#cccccc"))
        if self._notify_timer:
            self.root.after_cancel(self._notify_timer)
        self._notify_timer = self.root.after(duration, self._clear_notification)

    def _clear_notification(self):
        self._notify_label.configure(text="")
        self._notify_timer = None

    def append_system_message(self, message):
        """Add a system message to the current chat"""
        if self.selected_user:
            ts = time.strftime("%H:%M")
            self._add_message(self.selected_user, False, f"[System] {message}", ts)
        else:
            # No chat selected — show as toolbar notification instead of popup
            self._show_notification(str(message))

    def append_chat(self, source, message, color=None):
        """Legacy method - keep for system messages"""
        pass  # Bubble UI replaces this

    def _color_for_name(self, name):
        if name in self._name_colors:
            return self._name_colors[name]
        color = self._color_palette[len(self._name_colors) % len(self._color_palette)]
        self._name_colors[name] = color
        return color

    # ------------------------------------------------------------------
    # Callback Handling
    def on_message_received(self, msg_type, content):
        self.message_queue.put((msg_type, content))

    def process_messages(self):
        try:
            while True:
                msg_type, content = self.message_queue.get_nowait()
                self.handle_message(msg_type, content)
        except queue.Empty:
            pass
        self.root.after(100, self.process_messages)

    def handle_message(self, msg_type, content):
        if msg_type == 'SYS':
            self.append_system_message(content)
        elif msg_type == 'ERROR':
            if content == 'invite_required' and self._pending_register is not None:
                invite = self._dialog_input("Invite Code", "This server requires an invite code, please enter:")
                if invite:
                    self._pending_register['invite_code'] = invite
                    self.client.register(
                        self._pending_register['username'],
                        self._pending_register['password'],
                        store_private_key=self._pending_register['store_private_key'],
                        invite_code=invite,
                    )
                    return
            # Errors are critical — always show popup
            self._dialog_showerror("Error", str(content))
            # If this was a pending user verification, cancel it
            if self._pending_add_user:
                self._pending_add_user = None
            # Also add to chat if a user is selected
            if self.selected_user:
                ts = time.strftime("%H:%M")
                self._add_message(self.selected_user, False, f"[System] Error: {content}", ts)
        elif msg_type == 'SUCCESS':
            self.append_system_message(content)
            if isinstance(content, str) and 'Registration successful' in content:
                registered_username = None
                if self._pending_register:
                    registered_username = self._pending_register.get('username')
                self._pending_register = None
                self.root.after(500, lambda u=registered_username: self._show_own_fingerprint_after_register(u))
                self.root.after(800, lambda: self._show_recovery_key_prompt())
            self.update_button_states()
        elif msg_type == 'MESSAGE':
            if isinstance(content, dict):
                sender = content.get('sender', 'Message')
                message = content.get('message', '')
                ts = time.strftime("%H:%M")
                # Auto-add sender to user list if not already present
                if sender not in self._displayed_users:
                    self._displayed_users.append(sender)
                self._add_message(sender, False, message, ts)
                # Mark unread if not currently viewing this user
                if self.selected_user != sender:
                    self._user_unread[sender] = self._user_unread.get(sender, 0) + 1
                    self._update_user_list(self._displayed_users)
                # Flash taskbar
                if self.is_minimized_to_tray:
                    if isinstance(content, dict):
                        self._tray_notify(f"{content.get('sender', 'Message')}: {content.get('message', '')}")
                    else:
                        self._tray_notify(content)
                else:
                    flash_taskbar(self.root)
            else:
                self.append_system_message(content)
        elif msg_type == 'USERS':
            self._update_user_list(content)
        elif msg_type == 'WARNING':
            self.append_system_message(f"Warning: {content}")
        elif msg_type == 'USER_VERIFY':
            username = content.get('username', '')
            finger = content.get('fingerprint', '')
            approved = self._show_user_fingerprint_dialog(username, finger)
            if approved:
                self.client.trust_user(username)
            else:
                self.client._end_verification(username)
        elif msg_type == 'UPDATE_BUTTONS':
            self.update_button_states()
        elif msg_type == 'PUBKEY_OK':
            # A pubkey was successfully fetched — if this was a pending add, finalize it
            username = content
            if self._pending_add_user == username:
                self._pending_add_user = None
                if username not in self._displayed_users:
                    self._displayed_users.append(username)
                    self._update_user_list(self._displayed_users)
                self._select_user(username)
        else:
            self.append_system_message(str(content))

    # ------------------------------------------------------------------
    # User List - Modern Style with Unread Badges
    def _update_user_list(self, users):
        for widget in self.users_list_frame.winfo_children():
            widget.destroy()

        filtered_users = [u for u in users if u != self.client.username]
        # Merge: keep manually-added users that are not in the server list
        for u in self._displayed_users:
            if u not in filtered_users:
                filtered_users.append(u)
        self._displayed_users = filtered_users
        self._user_rows.clear()

        if self.selected_user and self.selected_user not in filtered_users:
            self.selected_user = None
            self._update_chat_header()
            self._render_messages()

        for u in filtered_users:
            trust_status = "✓" if self.client._is_user_trusted(u) else "?"
            unread_count = self._user_unread.get(u, 0)
            is_selected = (u == self.selected_user)
            p = self._pad

            # User row card
            if is_selected:
                bg_color = ("#e3f2fd", "#1e3a5f")
            elif unread_count > 0:
                bg_color = ("#fff3e0", "#3d2e1f")
            else:
                bg_color = ("#f5f5f5", "#2a2a3a")

            row = ctk.CTkFrame(self.users_list_frame, corner_radius=10, fg_color=bg_color)
            row.pack(fill=tk.X, pady=max(1, p['msg_pady']), padx=2)
            row.columnconfigure(1, weight=1)

            # Avatar
            av_sz = max(28, int(p['list_row_h'] * 0.85))
            avatar = ctk.CTkFrame(row, width=av_sz, height=av_sz, fg_color=self._color_for_name(u), corner_radius=av_sz // 2)
            avatar.grid(row=0, column=0, padx=(p['bubble_pad'], max(3, p['bubble_pad'] // 2)), pady=max(3, p['bubble_pad'] // 2))
            avatar.grid_propagate(False)

            avatar_label = ctk.CTkLabel(avatar, text=u[0].upper(), font=("Segoe UI", p['avatar_fs'], "bold"), text_color="white")
            avatar_label.place(relx=0.5, rely=0.5, anchor="center")

            # Name and info
            info_frame = ctk.CTkFrame(row, fg_color="transparent", corner_radius=0)
            info_frame.grid(row=0, column=1, sticky="nsew", pady=max(3, p['bubble_pad'] // 2))

            name_text = u
            if unread_count > 0:
                name_text = f"{u}  ({unread_count})"
                name_color = ("#e65100", "#ff9800")
                name_font = ("Segoe UI", p['list_fs'], "bold")
            else:
                name_color = ("#333333", "#e0e0e0")
                name_font = ("Segoe UI", p['list_fs'])

            name_label = ctk.CTkLabel(info_frame, text=name_text, font=name_font, text_color=name_color, anchor="w")
            name_label.pack(fill=tk.X)

            trust_label = ctk.CTkLabel(info_frame, text=f"Trust: {trust_status}", font=("Segoe UI", p['time_fs']), text_color=("#888888", "#666666"), anchor="w")
            trust_label.pack(fill=tk.X)

            # Status dot
            status_color = "#4caf50"  # Online
            dot_sz = max(6, int(p['avatar_sz'] * 0.3))
            status_dot = ctk.CTkFrame(row, width=dot_sz, height=dot_sz, fg_color=status_color, corner_radius=dot_sz // 2)
            status_dot.grid(row=0, column=2, padx=(max(3, p['bubble_pad'] // 2), p['bubble_pad']), pady=max(3, p['bubble_pad'] // 2))

            self._user_rows[u] = row
            self._bind_user_row_events(row, u)

    def refresh_online_users(self):
        if self.client and self.client.sock and self.client.session_id and self.client.session_key:
            self.client._request_online_users()
        self.root.after(self.USER_LIST_REFRESH_MS, self.refresh_online_users)

    def _bind_user_row_events(self, row, username):
        for widget in row.winfo_children():
            widget.bind("<Button-1>", lambda e, u=username: self._on_user_click(u))
            for child in widget.winfo_children():
                child.bind("<Button-1>", lambda e, u=username: self._on_user_click(u))
        row.bind("<Button-1>", lambda e, u=username: self._on_user_click(u))
        row.bind("<Double-1>", lambda e, u=username: self.on_user_double_click(u))
        row.bind("<Button-3>", lambda e, u=username: self.on_tree_right_click(e, u))

    def _on_user_click(self, username):
        self._select_user(username)

    def _select_user(self, username):
        self.selected_user = username
        # Clear unread
        if username in self._user_unread:
            del self._user_unread[username]
        self._update_user_list(self._displayed_users)
        self._update_chat_header()
        self._render_messages()

    def _update_chat_header(self):
        if self.selected_user:
            trust = "✓ Trusted" if self.client._is_user_trusted(self.selected_user) else "? Unverified"
            self.chat_header_label.configure(
                text=f"{self.selected_user}  •  {trust}",
                text_color=("#333333", "#e0e0e0")
            )
        else:
            self.chat_header_label.configure(
                text="Select a user to start chatting",
                text_color=("#666666", "#aaaaaa")
            )

    def _on_add_user_click(self):
        """Handle + button click to start chat with a new user"""
        username = self._dialog_input("New Chat", "Enter username to chat with:")
        if not username:
            return
        if not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            self._dialog_showerror("Error", "Invalid username format (3-20 alphanumeric)")
            return
        if username == self.client.username:
            self._dialog_showerror("Error", "Cannot chat with yourself")
            return

        # If user is already known (pubkey cached), add and select directly
        if username in self.client.user_pubkeys:
            if username not in self._displayed_users:
                self._displayed_users.append(username)
                self._update_user_list(self._displayed_users)
            self._select_user(username)
            return

        # User not yet verified — request pubkey first, add to list only on success
        self._pending_add_user = username
        self._show_notification(f"Verifying user {username}...")
        self.client._request_public_key(username)

    def on_tree_right_click(self, event, username=None):
        if username:
            self._select_user(username)
        if self.selected_user:
            self._show_context_menu(event.x_root, event.y_root, self.selected_user)

    def _show_context_menu(self, x, y, username):
        self._close_context_menu()
        self._context_menu_user = username
        menu = ctk.CTkToplevel(self.root)
        menu.overrideredirect(True)
        menu.attributes('-topmost', True)
        menu.geometry(f"180x160+{x}+{y}")

        container = ctk.CTkFrame(menu, corner_radius=8)
        container.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        ctk.CTkButton(container, text="Verify Fingerprint", corner_radius=8,
                      command=lambda: self._menu_action(self.verify_selected_user)).pack(fill=tk.X, padx=8, pady=(8, 4))
        ctk.CTkButton(container, text="Remove Trust", corner_radius=8,
                      command=lambda: self._menu_action(self.distrust_selected_user)).pack(fill=tk.X, padx=8, pady=4)
        ctk.CTkButton(container, text="Copy Fingerprint", corner_radius=8,
                      command=lambda: self._menu_action(self.copy_fingerprint)).pack(fill=tk.X, padx=8, pady=4)
        ctk.CTkButton(container, text="Close", corner_radius=8,
                      command=self._close_context_menu).pack(fill=tk.X, padx=8, pady=(4, 8))

        menu.bind("<FocusOut>", lambda e: self._close_context_menu())
        menu.focus_force()
        self._context_menu = menu

    def _menu_action(self, action):
        self._close_context_menu()
        action()

    def _close_context_menu(self):
        if self._context_menu:
            try:
                self._context_menu.destroy()
            except Exception:
                pass
        self._context_menu = None

    def on_user_double_click(self, username=None):
        if not username:
            username = self.selected_user
        if not username:
            return
        self._select_user(username)
        if username not in self.client.user_pubkeys:
            self.client._request_public_key(username)
        self.message_entry.focus()

    def verify_selected_user(self):
        username = self.selected_user
        if not username:
            return
        finger = self.client.get_user_fingerprint(username)
        if finger:
            self._show_user_fingerprint_dialog(username, finger)
            return

        with self.client.pending_manual_verifications_lock:
            if username in self.client.pending_manual_verifications:
                return
            self.client.pending_manual_verifications.add(username)
        self.append_system_message(f"Retrieving {username}'s public key for fingerprint verification...")
        self.client._request_public_key(username)

    def distrust_selected_user(self):
        username = self.selected_user
        if not username:
            return
        self.client.distrust_user(username)
        self._update_user_list(self._displayed_users)
        self._update_chat_header()

    def copy_fingerprint(self):
        username = self.selected_user
        if not username:
            return
        finger = self.client.get_user_fingerprint(username)
        if finger:
            self.root.clipboard_clear()
            self.root.clipboard_append(finger)
            self.append_system_message(f"Copied {username} fingerprint to clipboard")

    # ------------------------------------------------------------------
    # Fingerprint Dialog
    def _show_user_fingerprint_dialog(self, username, fingerprint):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("User Public Key Verification")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("700x430")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=f"Please verify with {username} the following fingerprint to confirm identity:", wraplength=600, font=("", 11, "bold")).pack(pady=10)

        from src.common.crypto_utils import FingerprintWords
        try:
            words = FingerprintWords.fingerprint_to_words(fingerprint, 6)
            words_str = "  ".join(words).upper()
        except Exception:
            words = None
            words_str = "(Cannot generate words)"

        word_frame = ctk.CTkFrame(dlg)
        word_frame.pack(pady=15, padx=20, fill=tk.X)
        ctk.CTkLabel(word_frame, text="Fingerprint Words (6):", font=("", 10, "bold")).pack(anchor="w", pady=(0, 8))
        ctk.CTkLabel(word_frame, text=words_str, font=("", 16, "bold"), text_color=("#0066ff", "#6699ff")).pack(anchor="w", pady=10, padx=10)

        ctk.CTkLabel(dlg, text="Verify these words with the other party through another secure channel (phone/in person).", wraplength=600, text_color=("orange", "orange"), font=("", 9)).pack(pady=5)

        result = [False]

        def verify():
            result[0] = True
            dlg.destroy()

        def cancel():
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=15)
        ctk.CTkButton(btn_frame, text="Verification Passed", command=verify, width=120, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="Cancel", command=cancel, width=120, corner_radius=8).pack(side=tk.LEFT, padx=5)

        dlg.bind('<Escape>', lambda e: cancel())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    def _show_own_fingerprint_dialog(self, title="My Fingerprint Words", display_name=None):
        if not self.client.id_pub:
            self._dialog_showerror("Error", "Identity information not ready")
            return

        words = self.client.get_own_fingerprint_words(6)
        fingerprint = self.client._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.client.id_pub)
        )

        if not words:
            self._dialog_showerror("Error", "Unable to generate fingerprint words")
            return

        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("700x390")
        dlg.resizable(True, True)

        display_name = display_name or self.client.username or "Current account"

        ctk.CTkLabel(dlg, text=f"Your Identity Fingerprint Words ({display_name}):", wraplength=600, font=("", 11, "bold")).pack(pady=10)

        word_frame = ctk.CTkFrame(dlg)
        word_frame.pack(pady=15, padx=20, fill=tk.X)
        ctk.CTkLabel(word_frame, text="Fingerprint Words (6):", font=("", 10, "bold")).pack(anchor="w", pady=(0, 8))
        words_str = "  ".join(words).upper()
        ctk.CTkLabel(word_frame, text=words_str, font=("", 16, "bold"), text_color=("#0066ff", "#6699ff")).pack(anchor="w", pady=10, padx=10)

        ctk.CTkLabel(dlg, text="You can share these words with others so they can verify your identity.", wraplength=600, text_color=("orange", "orange"), font=("", 9)).pack(pady=5)
        ctk.CTkLabel(dlg, text="Share these words through another secure channel (phone/in person).", wraplength=600, text_color=("orange", "orange"), font=("", 9)).pack(pady=(0, 10))

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=15)
        ctk.CTkButton(btn_frame, text="OK", command=dlg.destroy, width=100, corner_radius=8).pack(side=tk.LEFT, padx=5)

        dlg.bind('<Escape>', lambda e: dlg.destroy())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)

    def _show_own_fingerprint_after_register(self, username=None):
        self._show_own_fingerprint_dialog("My Fingerprint Words - Keep them safe", display_name=username)

    def _show_recovery_key_prompt(self):
        """Show recovery key backup prompt after successful registration."""
        if not hasattr(self.client, 'recovery_priv') or not self.client.recovery_priv:
            return
        username = self.client.username or "you"
        recovery_path = f'local_keys/{username}_recovery.priv'
        words = None
        try:
            from src.common.crypto_utils import FingerprintWords
            fp_hex = self.client._fingerprint_from_bytes(
                IdentityKeyManager.serialize_public_key(self.client.recovery_priv.public_key())
            )
            words = FingerprintWords.fingerprint_to_words(fp_hex, 6)
        except Exception:
            pass
        msg = (
            f"Your ACCOUNT RECOVERY KEY has been saved to:\n{recovery_path}\n\n"
            f"IMPORTANT: This key can permanently freeze your account.\n"
            f"Store it offline in a safe place (USB drive, paper, password manager).\n\n"
            f"Recovery words: {words if words else 'see saved file'}\n\n"
            f"If your account is compromised, use this key to freeze it permanently."
        )
        self._dialog_showinfo("Recovery Key Backup", msg)

    def _dialog_freeze_account(self):
        """Open emergency freeze dialog after clicking the freeze link on login screen."""
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Emergency Freeze")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("520x570")
        dlg.resizable(False, False)

        # Warning banner
        warn_frame = ctk.CTkFrame(dlg, fg_color=("#d32f2f", "#b71c1c"), corner_radius=8)
        warn_frame.pack(fill=tk.X, padx=20, pady=(20, 12))
        ctk.CTkLabel(
            warn_frame,
            text="⚠️  PERMANENT ACCOUNT FREEZE",
            font=("", 14, "bold"),
            text_color="white",
        ).pack(pady=(12, 6))
        ctk.CTkLabel(
            warn_frame,
            text="This action is IRREVERSIBLE. Once frozen,\nthe account can never be logged in or recovered.",
            font=("", 10),
            text_color="#ffcccc",
            justify=tk.CENTER,
        ).pack(pady=(0, 12))

        # Username
        ctk.CTkLabel(dlg, text="Username", font=("", 11)).pack(pady=(4, 4), padx=30, anchor="w")
        user_var = tk.StringVar()
        user_entry = ctk.CTkEntry(dlg, textvariable=user_var, width=440, corner_radius=6)
        user_entry.pack(pady=(0, 12), padx=30)
        user_entry.focus_set()

        # Recovery key file
        ctk.CTkLabel(dlg, text="Recovery Key File", font=("", 11)).pack(pady=(0, 4), padx=30, anchor="w")
        key_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        key_frame.pack(fill=tk.X, padx=30)
        key_var = tk.StringVar()
        key_entry = ctk.CTkEntry(key_frame, textvariable=key_var, width=340, corner_radius=6, state="readonly")
        key_entry.pack(side=tk.LEFT)

        def browse_key():
            path = filedialog.askopenfilename(
                parent=dlg,
                title="Select Recovery Key",
                filetypes=[("Private key files", "*.priv"), ("All files", "*.*")],
            )
            if path:
                key_var.set(path)

        ctk.CTkButton(key_frame, text="Browse", command=browse_key, width=80, corner_radius=6).pack(side=tk.LEFT, padx=(8, 0))

        # Confirmation checkbox
        confirm_var = tk.BooleanVar(value=False)
        confirm_cb = ctk.CTkCheckBox(
            dlg,
            text="I understand this action is irreversible and I have my recovery key ready.",
            variable=confirm_var,
            font=("", 11),
        )
        confirm_cb.pack(pady=(20, 8), padx=30, anchor="w")

        # Freeze button (only enabled when checkbox ticked)
        freeze_btn = ctk.CTkButton(
            dlg, text="Freeze Account", fg_color="#d32f2f", hover_color="#b71c1c",
            corner_radius=8, state="disabled", width=200,
        )
        freeze_btn.pack(pady=(6, 6))

        cancel_btn = ctk.CTkButton(
            dlg, text="Cancel", command=dlg.destroy, corner_radius=8, width=120,
        )
        cancel_btn.pack(pady=(0, 20))

        dlg.bind('<Escape>', lambda e: dlg.destroy())

        def on_check():
            if confirm_var.get():
                freeze_btn.configure(state="normal")
            else:
                freeze_btn.configure(state="disabled")

        confirm_cb.configure(command=on_check)
        freeze_btn.configure(command=lambda: self._do_freeze(user_var.get().strip(), key_var.get().strip(), dlg))

        self.center_dialog(dlg)
        dlg.update_idletasks()
        user_entry.focus_force()
        self.root.wait_window(dlg)

    def _do_freeze(self, username, key_path, dlg):
        """Attempt to permanently freeze an account using the recovery key."""
        if not username:
            self._dialog_showerror("Error", "Username cannot be empty")
            return
        if not key_path or not os.path.exists(key_path):
            self._dialog_showerror("Error", "Invalid recovery key file")
            return

        # Load recovery private key
        try:
            with open(key_path, "r", encoding="utf-8") as f:
                pem_data = f.read()
            recovery_priv = serialization.load_pem_private_key(
                pem_data.encode("utf-8"), password=None, backend=default_backend()
            )
        except Exception:
            self._dialog_showerror("Error", "Invalid recovery key file (not a valid PEM key)")
            return

        # Connect to server
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(10)
            raw_sock.connect((self.client.host, self.client.port))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.client.host)
            tls_sock.settimeout(10)
        except Exception as e:
            self._dialog_showerror("Error", f"Cannot connect to server: {e}")
            return

        try:
            receiver = PaddedReceiver()
            # Drain welcome
            receiver.recv(tls_sock)

            # Sign and send freeze command
            freeze_ts = int(time.time())
            nonce = secrets.token_hex(16)
            data_to_sign = f"{username}{freeze_ts}{nonce}".encode("utf-8")
            signature = recovery_priv.sign(data_to_sign).hex()

            cmd = {
                "cmd": "freeze_account",
                "data": {
                    "username": username,
                    "timestamp": freeze_ts,
                    "nonce": nonce,
                    "signature": signature,
                },
            }
            PaddedSender.send(tls_sock, json.dumps(cmd, ensure_ascii=False).encode("utf-8"))

            # Read response
            resp_raw = receiver.recv(tls_sock)
            if not resp_raw:
                self._dialog_showerror("Error", "No response from server")
                tls_sock.close()
                return

            resp = json.loads(resp_raw.decode("utf-8"))
            if resp.get("status") == "ok":
                dlg.destroy()
                self._dialog_showinfo(
                    "Account Frozen",
                    f"✅ Account '{username}' has been permanently frozen.\n\nThis account can never be logged in again.",
                )
            else:
                err = resp.get("error", "Unknown error")
                self._dialog_showerror("Freeze Failed", err)
        except Exception as e:
            self._dialog_showerror("Error", f"Freeze failed: {e}")
        finally:
            try:
                tls_sock.close()
            except Exception:
                pass

    def _on_user_label_click(self, event):
        if self.client.id_pub:
            self._show_own_fingerprint_dialog(display_name=self.client.username)
        else:
            self._dialog_showinfo("Info", "Identity information not ready")

    # ------------------------------------------------------------------
    # Tray and Exit
    def on_closing(self):
        self._quit_application()

    def on_window_unmap(self, event):
        if (not self.is_exiting and not self.is_minimized_to_tray and not self._tray_minimize_pending
                and self.root.state() == 'iconic'):
            self._tray_minimize_pending = True
            self.root.after(0, self.minimize_to_tray)

    def minimize_to_tray(self):
        self._tray_minimize_pending = False
        if pystray is None:
            self._quit_application()
            return
        if self.is_minimized_to_tray or self.tray_icon:
            return
        self.root.withdraw()
        self.is_minimized_to_tray = True
        image = Image.new('RGB', (64, 64), color=(30, 136, 229))
        draw = ImageDraw.Draw(image)
        draw.ellipse((10, 10, 54, 54), fill=(255, 255, 255))
        draw.ellipse((20, 20, 44, 44), fill=(30, 136, 229))
        menu = pystray.Menu(
            pystray.MenuItem('Open', lambda: self.root.after(0, self.restore_from_tray)),
            pystray.MenuItem('Exit', lambda: self.root.after(0, self._quit_application))
        )
        self.tray_icon = pystray.Icon('kaleido', image, 'KaleidoTalk', menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def restore_from_tray(self):
        self._tray_minimize_pending = False
        self.is_minimized_to_tray = False
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None

    def _tray_notify(self, msg):
        if self.tray_icon:
            self.tray_icon.notify(msg[:100], "New Message")

    def _quit_application(self):
        self.is_exiting = True
        self._tray_minimize_pending = False
        self._close_context_menu()
        # Save window geometry
        try:
            geo = self.root.geometry()  # e.g. "1100x760+100+50"
            m = re.match(r'(\d+)x(\d+)\+?(-?\d+)?\+?(-?\d+)?', geo)
            if m:
                w, h = int(m.group(1)), int(m.group(2))
                x = int(m.group(3)) if m.group(3) is not None else None
                y = int(m.group(4)) if m.group(4) is not None else None
                self._save_client_config(window={"width": w, "height": h, "x": x, "y": y})
        except Exception:
            pass
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
        self.client.logout()
        try:
            self.update_button_states()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ----------------------------------------------------------------------
def main():
    app = ChatGUI()
    app.run()


if __name__ == '__main__':
    print("KaleidoTalk Copyright (C) 2026 Bangze Han")
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under the terms of the GNU General Public License version 3 or later.")
    main()
