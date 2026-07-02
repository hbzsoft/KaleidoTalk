# chat_gui.py
# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


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
    ExchangeKeyManager,
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
    """Graphical User Interface - Modern KaleidoTalk V3.0"""

    USER_LIST_REFRESH_MS = 5000

    # ------------------------------------------------------------------
    # Config helpers
    def _load_client_config(self):
        """Load client_config.json; return None if first run."""
        if not os.path.exists(CONFIG_PATH):
            return None
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            for k, v in DEFAULT_CLIENT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
            return cfg
        except Exception:
            return None

    def _save_client_config(self, **overrides):
        """Save config atomically."""
        cfg = getattr(self, '_client_config', dict(DEFAULT_CLIENT_CONFIG))
        for k, v in overrides.items():
            if isinstance(v, dict):
                cfg.setdefault(k, {}).update(v)
            else:
                cfg[k] = v
        self._client_config = cfg
        if not os.path.exists("local_keys"):
            os.makedirs("local_keys")
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CONFIG_PATH)

    # ------------------------------------------------------------------

    def __init__(self):
        cfg = self._load_client_config()
        self._client_config = cfg if cfg else dict(DEFAULT_CLIENT_CONFIG)
        self._has_prev_config = cfg is not None

        ctk.set_appearance_mode(self._client_config.get("theme", "dark"))
        ctk.set_default_color_theme("dark-blue")
        self.root = ctk.CTk()
        default_font = ('Segoe UI', 10)
        self.root.option_add('*Font', default_font)
        self.root.option_add('*Dialog.msg.Font', default_font)
        self.root.title("KaleidoTalk V3.0")

        # Start with auth page size
        self.root.geometry("420x540")
        self.root.minsize(400, 500)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind("<Unmap>", self.on_window_unmap)

        # Center on screen
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - 420) // 2
        y = (sh - 540) // 2
        self.root.geometry(f"420x540+{x}+{y}")

        # Compute responsive scaling
        self._scale = max(0.7, min(1.3, min(sw / 1920, sh / 1080)))
        s = self._scale
        self._pad = {
            'main_x':     max(4, int(10 * s)),
            'main_y':     0,
            'toolbar_h':  max(32, int(38 * s)),
            'tb_padx':    max(4, int(6 * s)),
            'tb_btn_w':   max(68, int(82 * s)),
            'tb_btn_h':   max(26, int(30 * s)),
            'tb_btn_fs':  max(11, int(12 * s)),
            'tb_fs':      max(11, int(12 * s)),
            'content_gap':max(2, int(6 * s)),
            'header_h':   max(42, int(48 * s)),
            'header_fs':  max(11, int(13 * s)),
            'header_pad': max(8, int(12 * s)),
            'msg_padx':   max(4, int(8 * s)),
            'msg_pady':   max(2, int(3 * s)),
            'bubble_pad': max(6, int(10 * s)),
            'bubble_cr':  max(12, int(16 * s)),
            'avatar_sz':  max(30, int(36 * s)),
            'avatar_fs':  max(10, int(12 * s)),
            'msg_fs':     max(10, int(12 * s)),
            'time_fs':    max(8, int(9 * s)),
            'time_pad':   max(2, int(4 * s)),
            'send_padx':  max(8, int(12 * s)),
            'send_pady':  max(6, int(10 * s)),
            'entry_h':    max(36, int(42 * s)),
            'send_btn_w': max(72, int(92 * s)),
            'send_fs':    max(10, int(12 * s)),
            'left_w':     max(240, int(280 * s)),
            'list_row_h': max(46, int(54 * s)),
            'list_fs':    max(10, int(12 * s)),
            'spacer_w':   max(80, int(100 * s)),
        }

        self.message_queue = queue.Queue()
        self.client = ChatClient()
        self.client.callback = self.on_message_received
        self.client.cert_verify_callback = self._cert_verify_dialog

        srv = self._client_config.get("server", {})
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
        self._user_unread = {}
        self._pending_add_user = None
        self.selected_user = None
        self._messages = {}

        self._color_palette = [
            '#1f77b4', '#2ca02c', '#d62728', '#9467bd',
            '#ff7f0e', '#17becf', '#8c564b',
        ]
        self._name_colors = {}

        # Root grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Build both pages (hidden initially)
        self._build_auth_page()
        self._build_chat_page()

        # Determine startup path
        self.root.after(100, self.process_messages)
        self.root.after(150, self._startup_flow)

    # ==================================================================
    # Startup Flow
    # ==================================================================
    def _startup_flow(self):
        """Determine startup path based on whether config exists."""
        if not self._has_prev_config:
            # First run: ask for server address
            self._show_auth_page()
            self.root.after(100, self._show_server_input)
        elif self._client_config.get("server", {}).get("auto_connect", False):
            # Auto-connect silently
            self._show_auth_page()
            self.client.host = self._client_config["server"].get("host", "127.0.0.1")
            self.client.port = self._client_config["server"].get("port", 5555)
            ok = self.client.connect()
            if ok:
                self._auth_login_form()
            else:
                self._show_server_input()
        else:
            # Has config but no auto-connect: ask user
            self._show_auth_page()
            self.root.after(100, self._show_config_confirm)

    def _show_config_confirm(self):
        """Ask user whether to use previous configuration."""
        srv = self._client_config.get("server", {})
        host = srv.get("host", "127.0.0.1")
        port = srv.get("port", 5555)

        dlg = ctk.CTkToplevel(self.root)
        dlg.title("KaleidoTalk")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("400x260")
        dlg.resizable(False, False)

        ctk.CTkLabel(
            dlg, text="Welcome back to KaleidoTalk",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=(24, 8))

        ctk.CTkLabel(
            dlg,
            text="It looks like you've used KaleidoTalk before.\nWould you like to use your previous configuration?",
            font=("Segoe UI", 11),
            wraplength=340,
            justify=tk.CENTER,
        ).pack(pady=(0, 8))

        # Server info box
        info_frame = ctk.CTkFrame(dlg, fg_color=("#e8f0fe", "#1e2a3a"), corner_radius=8)
        info_frame.pack(pady=(4, 16), padx=40, fill=tk.X)
        ctk.CTkLabel(
            info_frame,
            text=f"Server: {host}:{port}",
            font=("Segoe UI", 11),
            text_color=("#1a73e8", "#8ab4f8"),
        ).pack(pady=8)

        result = [None]

        def on_yes():
            result[0] = True
            dlg.destroy()

        def on_no():
            result[0] = False
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack()
        ctk.CTkButton(
            btn_frame, text="Yes, connect", command=on_yes,
            width=140, corner_radius=8, height=36,
            font=("Segoe UI", 12),
        ).pack(side=tk.LEFT, padx=(0, 8))
        ctk.CTkButton(
            btn_frame, text="Use new address", command=on_no,
            width=140, corner_radius=8, height=36,
            font=("Segoe UI", 12),
            fg_color="transparent", border_width=1,
        ).pack(side=tk.LEFT)

        dlg.bind('<Escape>', lambda e: (result.__setitem__(0, False), dlg.destroy()))
        self._center_dialog(dlg)
        dlg.update_idletasks()
        dlg.focus_force()
        self.root.wait_window(dlg)

        if result[0] is True:
            self.client.host = host
            self.client.port = port
            ok = self.client.connect()
            if ok:
                self._auth_login_form()
            else:
                self._show_server_input()
        elif result[0] is False:
            self._show_server_input()

    def _show_server_input(self):
        """Ask for server address."""
        default = f"{self.client.host}:{self.client.port}"
        addr = self._dialog_input("Connect to Server", "Enter server address:", initial=default)
        if not addr:
            # User cancelled - if no config, just show auth page anyway
            if not self._has_prev_config and not self.client.sock:
                self._auth_login_form()
            return
        try:
            host, port = addr.split(':')
            port = int(port)
        except Exception:
            host, port = "127.0.0.1", 5555
        self.client.host = host
        self.client.port = port
        ok = self.client.connect()
        self._save_client_config(server={"host": host, "port": port})
        if ok:
            self._auth_login_form()
        else:
            self._dialog_showerror("Connection Failed", f"Could not connect to {host}:{port}")

    # ==================================================================
    # Auth Page
    # ==================================================================
    def _build_auth_page(self):
        """Build the auth page (login/register)."""
        self.auth_page = ctk.CTkFrame(self.root, corner_radius=0)
        self.auth_page.columnconfigure(0, weight=1)
        self.auth_page.rowconfigure(0, weight=1)
        self.auth_page.rowconfigure(1, weight=0)

        # Content area (centered card)
        self.auth_content = ctk.CTkFrame(self.auth_page, fg_color="transparent")
        self.auth_content.columnconfigure(0, weight=1)
        self.auth_content.grid(row=0, column=0, sticky="nsew", padx=40, pady=(40, 0))

        # About at bottom
        about_frame = ctk.CTkFrame(self.auth_page, fg_color="transparent", height=30)
        about_frame.grid(row=1, column=0, sticky="ew", padx=40, pady=(0, 12))
        about_btn = ctk.CTkButton(
            about_frame, text="About", command=self.show_about,
            fg_color="transparent",
            text_color=("#888888", "#666666"),
            font=("Segoe UI", 9, "underline"),
            hover_color=("#e8e8e8", "#2a2a3a"),
            width=60, height=24,
        )
        about_btn.pack()

        # Login form (default)
        self._auth_login_form()

    def _clear_auth_content(self):
        for w in self.auth_content.winfo_children():
            w.destroy()

    def _auth_login_form(self):
        """Show login form on auth page."""
        self._clear_auth_content()

        # Brand
        ctk.CTkLabel(
            self.auth_content,
            text="\U0001f510  KaleidoTalk",
            font=("Segoe UI", 20, "bold"),
            text_color=("#1a73e8", "#8ab4f8"),
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            self.auth_content,
            text="Log in to your\nKaleidoTalk Account",
            font=("Segoe UI", 15, "bold"),
            justify=tk.CENTER,
        ).pack(pady=(8, 24))

        # Username
        ctk.CTkLabel(
            self.auth_content, text="Username",
            font=("Segoe UI", 11),
            anchor="w",
        ).pack(padx=0, anchor="w")
        self._login_user_var = tk.StringVar()
        user_entry = ctk.CTkEntry(
            self.auth_content, textvariable=self._login_user_var,
            height=38, corner_radius=8, font=("Segoe UI", 12),
        )
        user_entry.pack(fill=tk.X, pady=(2, 12))
        user_entry.focus_set()

        # Password
        ctk.CTkLabel(
            self.auth_content, text="Password",
            font=("Segoe UI", 11),
            anchor="w",
        ).pack(padx=0, anchor="w")
        self._login_pw_var = tk.StringVar()
        pw_entry = ctk.CTkEntry(
            self.auth_content, textvariable=self._login_pw_var,
            height=38, corner_radius=8, font=("Segoe UI", 12),
            show="*",
        )
        pw_entry.pack(fill=tk.X, pady=(2, 16))

        # Login button
        login_btn = ctk.CTkButton(
            self.auth_content, text="Login",
            command=self._do_login_from_auth,
            height=40, corner_radius=8,
            font=("Segoe UI", 13, "bold"),
        )
        login_btn.pack(fill=tk.X, pady=(0, 20))

        # Bind Enter
        pw_entry.bind('<Return>', lambda e: self._do_login_from_auth())
        user_entry.bind('<Return>', lambda e: pw_entry.focus_set())

        # Register / Freeze links
        link_frame = ctk.CTkFrame(self.auth_content, fg_color="transparent")
        link_frame.pack()

        ctk.CTkButton(
            link_frame, text="Register",
            command=self._auth_register_form,
            fg_color="transparent",
            text_color=("#1a73e8", "#8ab4f8"),
            font=("Segoe UI", 11, "underline"),
            hover_color=("#e8f0fe", "#1e2a3a"),
            width=100, height=28,
        ).pack(side=tk.LEFT, padx=(0, 20))

        ctk.CTkButton(
            link_frame, text="Freeze Account",
            command=lambda: [self._dialog_freeze_account()],
            fg_color="transparent",
            text_color=("#888888", "#666666"),
            font=("Segoe UI", 11, "underline"),
            hover_color=("#e8e8e8", "#2a2a3a"),
            width=120, height=28,
        ).pack(side=tk.LEFT)

    def _auth_register_form(self):
        """Show register form on auth page."""
        self._clear_auth_content()

        # Brand
        ctk.CTkLabel(
            self.auth_content,
            text="\U0001f510  KaleidoTalk",
            font=("Segoe UI", 20, "bold"),
            text_color=("#1a73e8", "#8ab4f8"),
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            self.auth_content,
            text="Register Your\nKaleidoTalk Account",
            font=("Segoe UI", 15, "bold"),
            justify=tk.CENTER,
        ).pack(pady=(8, 20))

        # Username
        ctk.CTkLabel(
            self.auth_content, text="Username (3-20 alphanumeric)",
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(padx=0, anchor="w")
        self._reg_user_var = tk.StringVar()
        ctk.CTkEntry(
            self.auth_content, textvariable=self._reg_user_var,
            height=36, corner_radius=8, font=("Segoe UI", 12),
            placeholder_text="3-20 alphanumeric characters",
        ).pack(fill=tk.X, pady=(2, 10))

        # Password
        ctk.CTkLabel(
            self.auth_content, text="Password (letters + numbers, 8+ chars)",
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(padx=0, anchor="w")
        self._reg_pw_var = tk.StringVar()
        ctk.CTkEntry(
            self.auth_content, textvariable=self._reg_pw_var,
            height=36, corner_radius=8, font=("Segoe UI", 12),
            show="*", placeholder_text="At least 8 characters",
        ).pack(fill=tk.X, pady=(2, 14))

        # Key storage
        self._reg_store_var = tk.BooleanVar(value=True)
        storage_frame = ctk.CTkFrame(self.auth_content, fg_color="transparent")
        storage_frame.pack(fill=tk.X, pady=(0, 18))

        ctk.CTkLabel(
            storage_frame, text="Key Storage:",
            font=("Segoe UI", 10),
        ).pack(anchor="w")

        ctk.CTkRadioButton(
            storage_frame, text="Server (accessible from any device)",
            variable=self._reg_store_var, value=True,
            font=("Segoe UI", 11),
        ).pack(anchor="w", pady=(4, 2))

        ctk.CTkRadioButton(
            storage_frame, text="This device only",
            variable=self._reg_store_var, value=False,
            font=("Segoe UI", 11),
        ).pack(anchor="w")

        # Error label
        self._reg_error_label = ctk.CTkLabel(
            self.auth_content, text="",
            font=("Segoe UI", 10),
            text_color="#ff6b6b",
        )
        self._reg_error_label.pack(pady=(0, 8))

        # Register and Back buttons side by side
        btn_frame = ctk.CTkFrame(self.auth_content, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(4, 16))
        ctk.CTkButton(
            btn_frame, text="\u2190  Back",
            command=self._auth_login_form,
            fg_color="transparent", border_width=1,
            text_color=("#888888", "#aaaaaa"),
            font=("Segoe UI", 12),
            hover_color=("#e8e8e8", "#2a2a3a"),
            height=40, width=100,
        ).pack(side=tk.LEFT)
        ctk.CTkButton(
            btn_frame, text="Register",
            command=self._do_register_from_auth,
            height=40, corner_radius=8,
            font=("Segoe UI", 13, "bold"),
        ).pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(12, 0))

    def _ensure_connected(self):
        """Reconnect to server if socket is dead. Returns True if connected."""
        if self.client.sock:
            return True
        # Attempt reconnect silently
        ok = self.client.connect()
        if ok:
            return True
        return False

    def _do_login_from_auth(self):
        """Handle login from auth page."""
        username = self._login_user_var.get().strip()
        if not username or not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            self._dialog_showerror("Error", "Invalid username format (3-20 alphanumeric)")
            return
        pw = self._login_pw_var.get()
        if not pw:
            self._dialog_showerror("Error", "Password cannot be empty")
            return
        if not self._ensure_connected():
            self._dialog_showerror("Connection Lost", "Reconnect failed. Please check the server address.")
            return
        self._login_pw_var.set("")
        self.client.login(username, pw)

    def _do_register_from_auth(self):
        """Handle register from auth page."""
        if not self._ensure_connected():
            self._dialog_showerror("Connection Lost", "Reconnect failed. Please check the server address.")
            return
        if not self.client.server_ed25519_pub:
            self._dialog_showerror("Error", "Server public key not ready")
            return

        username = self._reg_user_var.get().strip()
        if not username or not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            self._reg_error_label.configure(text="Invalid username (3-20 alphanumeric)")
            return

        pw = self._reg_pw_var.get()
        if len(pw) < 8:
            self._reg_error_label.configure(text="Password must be at least 8 characters")
            return
        if not re.search(r'[A-Za-z]', pw) or not re.search(r'\d', pw):
            self._reg_error_label.configure(text="Password must include both letters and numbers")
            return

        self._reg_error_label.configure(text="")
        store_private_key = self._reg_store_var.get()

        if self.client.session_id and self.client.session_key:
            self.client.logout()

        self._pending_register = {
            'username': username,
            'password': pw,
            'store_private_key': store_private_key,
        }
        self.client.register(username, pw, store_private_key=store_private_key)

    def _show_auth_page(self):
        """Show the auth page."""
        self.chat_page.grid_forget()
        self.auth_page.grid(row=0, column=0, sticky="nsew")
        self.root.geometry("420x540")
        self.root.minsize(400, 500)
        # Center on screen
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - 420) // 2
        y = (sh - 540) // 2
        self.root.geometry(f"420x540+{x}+{y}")

    # ==================================================================
    # Chat Page
    # ==================================================================
    def _build_chat_page(self):
        """Build the main chat interface (hidden until login)."""
        self.chat_page = ctk.CTkFrame(self.root, corner_radius=0)
        self.chat_page.columnconfigure(0, weight=1)
        self.chat_page.rowconfigure(0, weight=1)
        self.chat_page.rowconfigure(1, weight=0)

        # Main content
        main_frame = ctk.CTkFrame(self.chat_page, corner_radius=0, fg_color="transparent")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=0)
        main_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=0)

        p = self._pad

        # ---- Top Bar ----
        toolbar = ctk.CTkFrame(main_frame, fg_color="transparent", height=p['toolbar_h'])
        toolbar.grid(row=0, column=0, sticky="ew", padx=p['main_x'])
        toolbar.grid_propagate(False)

        self.chat_user_label = ctk.CTkLabel(
            toolbar, text="", font=("Segoe UI", p['tb_fs'], "bold"),
            cursor="hand2",
        )
        self.chat_user_label.pack(side=tk.LEFT, padx=(0, p['tb_padx']))
        self.chat_user_label.bind("<Button-1>", self._on_user_label_click)

        self.logout_btn = ctk.CTkButton(
            toolbar, text="Logout", command=self.logout_user,
            corner_radius=6, width=max(60, p['tb_btn_w'] - 10),
            height=p['tb_btn_h'], font=("Segoe UI", p['tb_btn_fs']),
            fg_color=("#d32f2f", "#b71c1c"), hover_color=("#c62828", "#8e0000"),
        )
        self.logout_btn.pack(side=tk.RIGHT, padx=(p['tb_padx'], 0))

        # ---- Content Area ----
        content_frame = ctk.CTkFrame(main_frame, corner_radius=0, fg_color="transparent")
        content_frame.grid(row=1, column=0, sticky="nsew", padx=p['main_x'], pady=0)
        content_frame.columnconfigure(1, weight=1)
        content_frame.rowconfigure(0, weight=1)

        # Left Panel: User List
        left_panel = ctk.CTkFrame(content_frame, corner_radius=12, width=p['left_w'])
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, p['content_gap']))
        left_panel.grid_propagate(False)
        left_panel.columnconfigure(0, weight=1)
        left_panel.rowconfigure(1, weight=1)

        list_header = ctk.CTkFrame(left_panel, fg_color="transparent", height=p['header_h'])
        list_header.grid(row=0, column=0, sticky="ew", padx=p['header_pad'], pady=(p['header_pad'], max(2, p['header_pad'] // 2)))
        list_header.grid_propagate(False)
        list_header.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            list_header, text="Contacts",
            font=("Segoe UI", p['header_fs'], "bold"),
        ).grid(row=0, column=0, sticky="w")

        add_sz = max(20, int(p['header_h'] * 0.65))
        self.add_user_btn = ctk.CTkButton(
            list_header, text="+",
            font=("Segoe UI", max(12, int(p['header_fs'] * 1.2)), "bold"),
            width=add_sz, height=add_sz, corner_radius=add_sz // 2,
            command=self._on_add_user_click,
            fg_color=("#e0e0e0", "#3a3a3a"),
            hover_color=("#d0d0d0", "#4a4a4a"),
            text_color=("#333333", "#ffffff"),
        )
        self.add_user_btn.grid(row=0, column=1, sticky="e")

        self.users_list_frame = ctk.CTkScrollableFrame(left_panel, corner_radius=8, fg_color="transparent")
        self.users_list_frame.grid(row=1, column=0, sticky="nsew", padx=max(4, p['header_pad'] // 2), pady=(0, max(4, p['header_pad'] // 2)))
        self.users_list_frame.columnconfigure(0, weight=1)

        # Right Panel: Chat Area
        right_panel = ctk.CTkFrame(content_frame, corner_radius=12)
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.columnconfigure(0, weight=1)
        right_panel.rowconfigure(0, weight=0)
        right_panel.rowconfigure(1, weight=1)
        right_panel.rowconfigure(2, weight=0)

        # Chat header
        self.chat_header = ctk.CTkFrame(right_panel, fg_color="transparent", height=p['header_h'])
        self.chat_header.grid(row=0, column=0, sticky="ew", padx=p['header_pad'], pady=(p['header_pad'], max(2, p['header_pad'] // 2)))
        self.chat_header.grid_propagate(False)

        self.chat_header_label = ctk.CTkLabel(
            self.chat_header, text="Select a user to start chatting",
            font=("Segoe UI", p['header_fs'], "bold"),
            text_color=("#666666", "#aaaaaa"),
        )
        self.chat_header_label.pack(side=tk.LEFT)

        # Messages canvas
        self.messages_canvas = tk.Canvas(right_panel, highlightthickness=0, bg="#1a1a2e")
        self.messages_canvas.grid(row=1, column=0, sticky="nsew", padx=p['msg_padx'], pady=max(2, p['msg_pady']))
        self.messages_canvas.columnconfigure(0, weight=1)

        self.messages_scrollbar = ctk.CTkScrollbar(right_panel, command=self.messages_canvas.yview)
        self.messages_scrollbar.grid(row=1, column=1, sticky="ns", pady=max(2, p['msg_pady']))
        self.messages_canvas.configure(yscrollcommand=self.messages_scrollbar.set)

        self.messages_frame = ctk.CTkFrame(self.messages_canvas, fg_color="transparent", corner_radius=0)
        self.messages_canvas_window = self.messages_canvas.create_window(
            (0, 0), window=self.messages_frame, anchor="nw",
            width=self.messages_canvas.winfo_width(),
        )
        self.messages_frame.bind("<Configure>", self._on_messages_frame_configure)
        self.messages_canvas.bind("<Configure>", self._on_canvas_configure)
        self.messages_canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Send Area
        send_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        send_frame.grid(row=2, column=0, sticky="ew", padx=p['send_padx'], pady=(p['send_pady'], 0))
        send_frame.columnconfigure(0, weight=1)
        send_frame.columnconfigure(1, weight=0)

        self.message_entry = ctk.CTkEntry(
            send_frame, corner_radius=20, height=p['entry_h'],
            placeholder_text="Type a message...",
            font=("Segoe UI", p['send_fs']),
            state=tk.DISABLED,
        )
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, max(4, p['send_padx'] // 2)))
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        self.send_btn = ctk.CTkButton(
            send_frame, text="Send", command=self.send_message,
            state=tk.DISABLED, corner_radius=20, width=p['send_btn_w'],
            height=p['entry_h'], font=("Segoe UI", p['send_fs'], "bold"),
        )
        self.send_btn.grid(row=0, column=1)

        # About at bottom of chat
        about_frame2 = ctk.CTkFrame(right_panel, fg_color="transparent", height=24)
        about_frame2.grid(row=3, column=0, sticky="e", padx=p['send_padx'], pady=(p['send_pady'], p['send_pady']))
        ctk.CTkButton(
            about_frame2, text="About", command=self.show_about,
            fg_color="transparent",
            text_color=("#999999", "#666666"),
            font=("Segoe UI", 9, "underline"),
            hover_color=("#e8e8e8", "#2a2a3a"),
            width=50, height=20,
        ).pack()

    def _switch_to_chat(self):
        """Switch from auth page to chat page after login."""
        self.auth_page.grid_forget()
        self.chat_page.grid(row=0, column=0, sticky="nsew")

        win = self._client_config.get("window", {})
        w = win.get("width", 1100) or 1100
        h = win.get("height", 760) or 760
        x = win.get("x")
        y = win.get("y")
        if x is not None and y is not None:
            self.root.geometry(f"{w}x{h}+{int(x)}+{int(y)}")
        else:
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            w = min(1180, max(960, sw - 120))
            h = min(820, max(700, sh - 120))
            x = (sw - w) // 2
            y = (sh - h) // 2
            self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.minsize(960, 700)

        self.chat_user_label.configure(text=f"Welcome, {self.client.username}")
        self.message_entry.configure(state=tk.NORMAL)
        self.send_btn.configure(state=tk.NORMAL)
        self.root.after(100, self._request_online_users)
        self.root.after(self.USER_LIST_REFRESH_MS, self.refresh_online_users)

    def _request_online_users(self):
        """Request online user list from server."""
        if self.client and self.client.sock and self.client.session_id and self.client.session_key:
            self.client._request_online_users()

    # ==================================================================
    # Messages Canvas scrolling
    # ==================================================================
    def _on_messages_frame_configure(self, event=None):
        self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))

    def _on_canvas_configure(self, event=None):
        self.messages_canvas.itemconfig(self.messages_canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        self.messages_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _scroll_to_bottom(self):
        self.messages_canvas.update_idletasks()
        self.messages_canvas.yview_moveto(1.0)

    # ==================================================================
    # Message Sending and Display - Bubble Style
    # ==================================================================
    def send_message(self):
        if not self.selected_user:
            return
        msg = self.message_entry.get().strip()
        if not msg:
            return
        if self.client.send_message(self.selected_user, msg):
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
        for widget in self.messages_frame.winfo_children():
            widget.destroy()

        if not self.selected_user or self.selected_user not in self._messages:
            placeholder = ctk.CTkLabel(
                self.messages_frame,
                text="No messages yet\nStart a conversation!",
                font=("Segoe UI", 12),
                text_color=("#999999", "#666666"),
            )
            placeholder.pack(pady=100)
            return

        messages = self._messages.get(self.selected_user, [])
        for is_self, message, timestamp in messages:
            self._create_bubble_message(is_self, message, timestamp)

        self.root.after(50, self._scroll_to_bottom)

    def _create_bubble_message(self, is_self, message, timestamp):
        """Create a bubble message widget with proper spacing."""
        p = self._pad
        outer = tk.Frame(self.messages_frame, bg="#1a1a2e")
        outer.pack(fill=tk.X, padx=0, pady=(0, max(4, p['msg_pady'] * 2)))

        if is_self:
            outer.columnconfigure(0, weight=1)
            # Spacer on left
            spacer = tk.Frame(outer, width=p['spacer_w'], bg="#1a1a2e")
            spacer.grid(row=0, column=0, sticky="nsew")

            bubble = ctk.CTkFrame(
                outer, fg_color=("#0078d4", "#0078d4"), corner_radius=p['bubble_cr'],
            )
            bubble.grid(row=0, column=1, sticky="e", padx=(0, p['msg_padx']))

            msg_label = ctk.CTkLabel(
                bubble, text=message,
                font=("Segoe UI", p['msg_fs']),
                text_color="white", wraplength=400, justify=tk.LEFT,
            )
            msg_label.pack(padx=p['bubble_pad'], pady=(p['bubble_pad'] // 2, 0))

            time_label = ctk.CTkLabel(
                bubble, text=timestamp,
                font=("Segoe UI", p['time_fs']),
                text_color=("#aaddff", "#88bbdd"), anchor="e",
            )
            time_label.pack(fill=tk.X, padx=p['bubble_pad'], pady=(0, max(2, p['bubble_pad'] // 3)))
        else:
            outer.columnconfigure(1, weight=1)

            # Avatar circle
            avatar = ctk.CTkFrame(
                outer, width=p['avatar_sz'], height=p['avatar_sz'],
                fg_color=self._color_for_name(self.selected_user),
                corner_radius=p['avatar_sz'] // 2,
            )
            avatar.grid(row=0, column=0, padx=(p['msg_padx'], max(4, p['bubble_pad'] // 2)), sticky="n")
            avatar.grid_propagate(False)

            avatar_label = ctk.CTkLabel(
                avatar, text=self.selected_user[0].upper(),
                font=("Segoe UI", p['avatar_fs'], "bold"), text_color="white",
            )
            avatar_label.place(relx=0.5, rely=0.5, anchor="center")

            bubble = ctk.CTkFrame(
                outer, fg_color=("#f0f0f0", "#2d2d3a"), corner_radius=p['bubble_cr'],
            )
            bubble.grid(row=0, column=1, sticky="w")

            msg_label = ctk.CTkLabel(
                bubble, text=message,
                font=("Segoe UI", p['msg_fs']),
                text_color=("#333333", "#e0e0e0"), wraplength=400, justify=tk.LEFT,
            )
            msg_label.pack(padx=p['bubble_pad'], pady=(p['bubble_pad'] // 2, 0))

            time_label = ctk.CTkLabel(
                bubble, text=timestamp,
                font=("Segoe UI", p['time_fs']),
                text_color=("#999999", "#777777"), anchor="w",
            )
            time_label.pack(fill=tk.X, padx=p['bubble_pad'], pady=(0, max(2, p['bubble_pad'] // 3)))

            # Spacer on right
            spacer = tk.Frame(outer, width=p['spacer_w'], bg="#1a1a2e")
            spacer.grid(row=0, column=2, sticky="nsew")

    def _color_for_name(self, name):
        if name in self._name_colors:
            return self._name_colors[name]
        color = self._color_palette[len(self._name_colors) % len(self._color_palette)]
        self._name_colors[name] = color
        return color

    # ==================================================================
    # Callback Handling
    # ==================================================================
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
            self._append_system_message(content)
        elif msg_type == 'ERROR':
            if content == 'invite_required' and self._pending_register is not None:
                invite = self._dialog_input("Invite Code", "This server requires an invite code:")
                if invite:
                    self._pending_register['invite_code'] = invite
                    self.client.register(
                        self._pending_register['username'],
                        self._pending_register['password'],
                        store_private_key=self._pending_register['store_private_key'],
                        invite_code=invite,
                    )
                    return
            self._dialog_showerror("Error", str(content))
            if self._pending_add_user:
                self._pending_add_user = None
            if self.selected_user:
                ts = time.strftime("%H:%M")
                self._add_message(self.selected_user, False, f"[System] Error: {content}", ts)
        elif msg_type == 'SUCCESS':
            self._append_system_message(content)
            if isinstance(content, str) and 'Login successful' in content:
                self.root.after(100, self._switch_to_chat)
            elif isinstance(content, str) and 'Registration successful' in content:
                registered_username = None
                reg_password = None
                if self._pending_register:
                    registered_username = self._pending_register.get('username')
                    reg_password = self._pending_register.get('password')
                self._pending_register = None
                # Clear form fields
                self._reg_user_var.set("")
                self._reg_pw_var.set("")
                self.root.after(500, lambda u=registered_username: self._show_own_fingerprint_after_register(u))
                self.root.after(800, lambda: self._show_recovery_key_dialog())
                # Auto-login after dialogs
                if registered_username and reg_password:
                    self.root.after(1500, lambda u=registered_username, p=reg_password: self._auto_login_after_register(u, p))
        elif msg_type == 'MESSAGE':
            if isinstance(content, dict):
                sender = content.get('sender', 'Message')
                message = content.get('message', '')
                ts = time.strftime("%H:%M")
                if sender not in self._displayed_users:
                    self._displayed_users.append(sender)
                self._add_message(sender, False, message, ts)
                if self.selected_user != sender:
                    self._user_unread[sender] = self._user_unread.get(sender, 0) + 1
                    self._update_user_list(self._displayed_users)
                if self.is_minimized_to_tray:
                    self._tray_notify(f"{content.get('sender', '')}: {content.get('message', '')}")
                else:
                    flash_taskbar(self.root)
            else:
                self._append_system_message(content)
        elif msg_type == 'USERS':
            self._update_user_list(content)
        elif msg_type == 'WARNING':
            self._append_system_message(f"Warning: {content}")
        elif msg_type == 'USER_VERIFY':
            username = content.get('username', '')
            finger = content.get('fingerprint', '')
            approved = self._show_user_fingerprint_dialog(username, finger)
            if approved:
                self.client.trust_user(username)
            else:
                self.client._end_verification(username)
        elif msg_type == 'UPDATE_BUTTONS':
            pass  # No more button states to update
        elif msg_type == 'PUBKEY_OK':
            username = content
            if self._pending_add_user == username:
                self._pending_add_user = None
                if username not in self._displayed_users:
                    self._displayed_users.append(username)
                    self._update_user_list(self._displayed_users)
                self._select_user(username)
        else:
            self._append_system_message(str(content))

    def _append_system_message(self, message):
        if self.selected_user:
            ts = time.strftime("%H:%M")
            self._add_message(self.selected_user, False, f"[System] {message}", ts)

    # ==================================================================
    # User List
    # ==================================================================
    def _update_user_list(self, users):
        for widget in self.users_list_frame.winfo_children():
            widget.destroy()

        filtered_users = [u for u in users if u != self.client.username]
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
            trust_status = "\u2713" if self.client._is_user_trusted(u) else "?"
            unread_count = self._user_unread.get(u, 0)
            is_selected = (u == self.selected_user)
            p = self._pad

            if is_selected:
                bg_color = ("#e3f2fd", "#1e3a5f")
            elif unread_count > 0:
                bg_color = ("#fff3e0", "#3d2e1f")
            else:
                bg_color = ("#f5f5f5", "#2a2a3a")

            row = ctk.CTkFrame(self.users_list_frame, corner_radius=10, fg_color=bg_color)
            row.pack(fill=tk.X, pady=max(1, p['msg_pady']), padx=2)
            row.columnconfigure(1, weight=1)

            av_sz = max(28, int(p['list_row_h'] * 0.85))
            avatar = ctk.CTkFrame(row, width=av_sz, height=av_sz, fg_color=self._color_for_name(u), corner_radius=av_sz // 2)
            avatar.grid(row=0, column=0, padx=(p['bubble_pad'], max(3, p['bubble_pad'] // 2)), pady=max(3, p['bubble_pad'] // 2))
            avatar.grid_propagate(False)

            a_label = ctk.CTkLabel(avatar, text=u[0].upper(), font=("Segoe UI", p['avatar_fs'], "bold"), text_color="white")
            a_label.place(relx=0.5, rely=0.5, anchor="center")

            info_frame = ctk.CTkFrame(row, fg_color="transparent", corner_radius=0)
            info_frame.grid(row=0, column=1, sticky="nsew", pady=max(3, p['bubble_pad'] // 2))

            if unread_count > 0:
                name_text = f"{u}  ({unread_count})"
                name_color = ("#e65100", "#ff9800")
                name_font = ("Segoe UI", p['list_fs'], "bold")
            else:
                name_text = u
                name_color = ("#333333", "#e0e0e0")
                name_font = ("Segoe UI", p['list_fs'])

            name_label = ctk.CTkLabel(info_frame, text=name_text, font=name_font, text_color=name_color, anchor="w")
            name_label.pack(fill=tk.X)

            trust_label = ctk.CTkLabel(
                info_frame, text=f"Trust: {trust_status}",
                font=("Segoe UI", p['time_fs']),
                text_color=("#888888", "#666666"), anchor="w",
            )
            trust_label.pack(fill=tk.X)

            dot_sz = max(6, int(p['avatar_sz'] * 0.3))
            status_dot = ctk.CTkFrame(row, width=dot_sz, height=dot_sz, fg_color="#4caf50", corner_radius=dot_sz // 2)
            status_dot.grid(row=0, column=2, padx=(max(3, p['bubble_pad'] // 2), p['bubble_pad']), pady=max(3, p['bubble_pad'] // 2))

            self._user_rows[u] = row
            self._bind_user_row_events(row, u)

    def refresh_online_users(self):
        if self.client and self.client.sock and self.client.session_id and self.client.session_key:
            self.client._request_online_users()
        self.root.after(self.USER_LIST_REFRESH_MS, self.refresh_online_users)

    def _bind_user_row_events(self, row, username):
        for widget in row.winfo_children():
            widget.bind("<Button-1>", lambda e, u=username: self._select_user(u))
            widget.bind("<Button-3>", lambda e, u=username: self.on_tree_right_click(e, u))
            if isinstance(widget, ctk.CTkFrame):
                self._bind_user_row_events(widget, username)

    def _select_user(self, username):
        self.selected_user = username
        if username in self._user_unread:
            del self._user_unread[username]
        self._update_user_list(self._displayed_users)
        self._update_chat_header()
        self._render_messages()
        # Request pubkey if we don't have it yet for sending
        if username not in self.client.user_pubkeys:
            self.client._request_public_key(username)

    def _update_chat_header(self):
        if self.selected_user:
            trust = "\u2713 Trusted" if self.client._is_user_trusted(self.selected_user) else "? Unverified"
            self.chat_header_label.configure(
                text=f"{self.selected_user}  \u2022  {trust}",
                text_color=("#333333", "#e0e0e0"),
            )
        else:
            self.chat_header_label.configure(
                text="Select a user to start chatting",
                text_color=("#666666", "#aaaaaa"),
            )

    def _on_add_user_click(self):
        username = self._dialog_input("New Chat", "Enter username to chat with:")
        if not username:
            return
        if not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            self._dialog_showerror("Error", "Invalid username format (3-20 alphanumeric)")
            return
        if username == self.client.username:
            self._dialog_showerror("Error", "Cannot chat with yourself")
            return
        if username in self.client.user_pubkeys:
            if username not in self._displayed_users:
                self._displayed_users.append(username)
                self._update_user_list(self._displayed_users)
            self._select_user(username)
            return
        self._pending_add_user = username
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

        ctk.CTkButton(
            container, text="Verify Fingerprint", corner_radius=8,
            command=lambda: self._menu_action(self.verify_selected_user),
        ).pack(fill=tk.X, padx=8, pady=(8, 4))
        ctk.CTkButton(
            container, text="Remove Trust", corner_radius=8,
            command=lambda: self._menu_action(self.distrust_selected_user),
        ).pack(fill=tk.X, padx=8, pady=4)
        ctk.CTkButton(
            container, text="Copy Fingerprint", corner_radius=8,
            command=lambda: self._menu_action(self.copy_fingerprint),
        ).pack(fill=tk.X, padx=8, pady=4)
        ctk.CTkButton(
            container, text="Close", corner_radius=8,
            command=self._close_context_menu,
        ).pack(fill=tk.X, padx=8, pady=(4, 8))

        menu.bind("<FocusOut>", lambda e: self._close_context_menu())
        menu.focus_force()
        self._context_menu = menu

    def _menu_action(self, action):
        self._close_context_menu()
        action()

    def _close_context_menu(self):
        if self._context_menu:
            self._context_menu.destroy()
            self._context_menu = None
            self._context_menu_user = None

    def verify_selected_user(self):
        if not self.selected_user:
            return
        if self.selected_user in self.client.user_pubkeys:
            pub = self.client.user_pubkeys[self.selected_user].get('ed25519')
            if pub:
                from src.common.crypto_utils import FingerprintWords
                fp_hex = self.client._fingerprint_from_bytes(
                    IdentityKeyManager.serialize_public_key(pub)
                )
                words = FingerprintWords.fingerprint_to_words(fp_hex, 6)
                self._show_user_fingerprint_dialog(self.selected_user, fp_hex, words=words)

    def distrust_selected_user(self):
        if self.selected_user:
            self.client.distrust_user(self.selected_user)
            self._update_chat_header()

    def copy_fingerprint(self):
        """Copy the fingerprint of the selected user to clipboard."""
        if not self.selected_user:
            return
        if self.selected_user in self.client.user_pubkeys:
            pub = self.client.user_pubkeys[self.selected_user].get('ed25519')
            if pub:
                fp_hex = self.client._fingerprint_from_bytes(
                    IdentityKeyManager.serialize_public_key(pub)
                )
                self.root.clipboard_clear()
                self.root.clipboard_append(fp_hex)

    # ==================================================================
    # Login / Logout
    # ==================================================================
    def login_user(self):
        """Legacy login entry - now handled via auth page."""
        pass

    def register_user(self):
        """Legacy register entry - now handled via auth page."""
        pass

    def logout_user(self):
        self.client.logout()
        self.selected_user = None
        self._messages.clear()
        self._displayed_users.clear()
        self._user_rows.clear()
        self._user_unread.clear()
        self._name_colors.clear()
        self._update_user_list([])
        self._update_chat_header()
        self._render_messages()
        self._show_auth_page()
        # Reset to login form
        self._auth_login_form()

    def _auto_login_after_register(self, username, password):
        """Auto-login after successful registration and dialog flow."""
        if not self._ensure_connected():
            self._dialog_showerror("Connection Lost", "Reconnect failed. Please check the server address.")
            return
        # Set the login form fields and trigger login
        self._login_user_var.set(username)
        self._login_pw_var.set(password)
        self._auth_login_form()
        self.client.login(username, password)

    # ==================================================================
    # Dialog Helpers
    # ==================================================================
    def _dialog_input(self, title, prompt, show=None, initial=''):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("420x200")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=prompt, wraplength=350, font=("Segoe UI", 11)).pack(pady=(20, 10), padx=20)
        var = tk.StringVar(value=initial)
        entry = ctk.CTkEntry(dlg, textvariable=var, width=340, show=show, corner_radius=8, font=("Segoe UI", 11))
        entry.pack(pady=(0, 10))
        entry.focus_set()
        result = None

        def on_ok():
            nonlocal result
            result = var.get()
            dlg.destroy()

        entry.bind('<Return>', lambda e: on_ok())
        entry.bind('<Escape>', lambda e: dlg.destroy())
        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack()
        ctk.CTkButton(btn_frame, text="OK", command=on_ok, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="Cancel", command=dlg.destroy, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)

        self._center_dialog(dlg)
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
        dlg.geometry("520x300")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=message, justify=tk.LEFT, wraplength=450, font=("Segoe UI", 11)).pack(pady=(20, 10), padx=20)
        sel_var = tk.IntVar(value=-1)
        for i, (label, val) in enumerate(choices):
            ctk.CTkRadioButton(
                dlg, text=label, variable=sel_var, value=i,
                font=("Segoe UI", 11),
            ).pack(anchor="w", padx=40, pady=4)

        result = [None]

        def on_ok():
            idx = sel_var.get()
            if 0 <= idx < len(choices):
                result[0] = choices[idx][1]
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=15)
        ctk.CTkButton(btn_frame, text="OK", command=on_ok, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="Cancel", command=dlg.destroy, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)

        self._center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    def _dialog_showinfo(self, title, message):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("480x380")
        dlg.resizable(True, True)
        ctk.CTkLabel(dlg, text=message, wraplength=420, justify=tk.LEFT, font=("Segoe UI", 11)).pack(pady=20, padx=20)
        ctk.CTkButton(dlg, text="OK", command=dlg.destroy, width=100, corner_radius=8).pack(pady=10)
        self._center_dialog(dlg)
        self.root.wait_window(dlg)

    def _dialog_showerror(self, title, message):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("420x200")
        dlg.resizable(True, True)
        ctk.CTkLabel(
            dlg, text=message, wraplength=360, justify=tk.LEFT,
            font=("Segoe UI", 11), text_color="#ff6b6b",
        ).pack(pady=20, padx=20)
        ctk.CTkButton(dlg, text="OK", command=dlg.destroy, width=100, corner_radius=8).pack(pady=10)
        self._center_dialog(dlg)
        self.root.wait_window(dlg)

    def _center_dialog(self, dialog):
        dialog.update_idletasks()
        req_w = max(dialog.winfo_width(), dialog.winfo_reqwidth())
        req_h = max(dialog.winfo_height(), dialog.winfo_reqheight())
        sw = dialog.winfo_screenwidth()
        sh = dialog.winfo_screenheight()
        w = min(req_w, max(320, sw - 80))
        h = min(req_h, max(180, sh - 120))
        x = max(0, (sw // 2) - (w // 2))
        y = max(0, (sh // 2) - (h // 2))
        dialog.geometry(f'{w}x{h}+{x}+{y}')

    # ==================================================================
    # TLS Certificate Verification Dialog
    # ==================================================================
    def _cert_verify_dialog(self, endpoint, fingerprint):
        words = FingerprintWords.fingerprint_to_words(fingerprint, 6)
        words_list = words if words else ["??????"] * 6

        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Security Verification")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("600x440")
        dlg.resizable(True, True)

        # Warning banner
        warn_frame = ctk.CTkFrame(dlg, fg_color=("#e65100", "#bf360c"), corner_radius=8)
        warn_frame.pack(fill=tk.X, padx=20, pady=(20, 12))
        ctk.CTkLabel(
            warn_frame,
            text="\u26a0\ufe0f  VERIFY SERVER IDENTITY",
            font=("Segoe UI", 14, "bold"), text_color="white",
        ).pack(pady=(12, 4))
        ctk.CTkLabel(
            warn_frame,
            text="First time connecting to this server.\nVerify before proceeding.",
            font=("Segoe UI", 10), text_color="#ffcc80", justify=tk.CENTER,
        ).pack(pady=(0, 12))

        ctk.CTkLabel(
            dlg, text=f"Server: {endpoint}",
            font=("Segoe UI", 11, "bold"),
        ).pack(pady=(12, 8))

        # Fingerprint words
        fprint_frame = ctk.CTkFrame(dlg, fg_color=("#f5f5f5", "#1a1a2e"), corner_radius=10)
        fprint_frame.pack(pady=(4, 12), padx=20, fill=tk.X)
        ctk.CTkLabel(
            fprint_frame,
            text="FINGERPRINT WORDS (BIP39):",
            font=("Segoe UI", 10, "bold"),
            text_color=("#666666", "#888888"),
        ).pack(anchor="w", pady=(10, 8), padx=16)

        row1 = "    ".join(words_list[:3]).upper()
        row2 = "    ".join(words_list[3:6]).upper()
        ctk.CTkLabel(
            fprint_frame, text=row1,
            font=("Consolas", 16, "bold"),
            text_color=("#0066cc", "#6699ff"),
        ).pack(anchor="w", padx=20, pady=(0, 2))
        ctk.CTkLabel(
            fprint_frame, text=row2,
            font=("Consolas", 16, "bold"),
            text_color=("#0066cc", "#6699ff"),
        ).pack(anchor="w", padx=20, pady=(0, 10))

        # Warning footer
        ctk.CTkLabel(
            dlg,
            text="\u26a0  Confirm via another secure channel\n    (phone call, in person) before trusting.",
            font=("Segoe UI", 9),
            text_color=("#e65100", "#ff9800"),
            justify=tk.CENTER,
        ).pack(pady=(0, 12))

        result = [False]

        def trust():
            result[0] = True
            dlg.destroy()

        def reject():
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=(4, 16))
        ctk.CTkButton(
            btn_frame, text="Trust & Connect", command=trust,
            width=150, corner_radius=8, height=36,
            fg_color=("#2e7d32", "#388e3c"),
            hover_color=("#1b5e20", "#2e7d32"),
            font=("Segoe UI", 12, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 12))
        ctk.CTkButton(
            btn_frame, text="Cancel", command=reject,
            width=120, corner_radius=8, height=36,
            fg_color="transparent", border_width=1,
            font=("Segoe UI", 12),
        ).pack(side=tk.LEFT)

        dlg.bind('<Escape>', lambda e: reject())
        self._center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    # ==================================================================
    # Fingerprint Dialogs
    # ==================================================================
    def _show_own_fingerprint_dialog(self, title="Identity Fingerprint", display_name=None):
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
        dlg.geometry("600x400")
        dlg.resizable(True, True)

        display_name = display_name or self.client.username or "Current account"

        ctk.CTkLabel(
            dlg, text=f"Your Identity Fingerprint ({display_name}):",
            font=("Segoe UI", 13, "bold"), wraplength=540,
        ).pack(pady=(20, 8))

        fprint_frame = ctk.CTkFrame(dlg, fg_color=("#f5f5f5", "#1a1a2e"), corner_radius=10)
        fprint_frame.pack(pady=(4, 12), padx=20, fill=tk.X)
        ctk.CTkLabel(
            fprint_frame,
            text="IDENTITY FINGERPRINT (BIP39):",
            font=("Segoe UI", 10, "bold"),
            text_color=("#666666", "#888888"),
        ).pack(anchor="w", pady=(10, 8), padx=16)

        row1 = "    ".join(words[:3]).upper()
        row2 = "    ".join(words[3:6]).upper()
        ctk.CTkLabel(
            fprint_frame, text=row1,
            font=("Consolas", 16, "bold"),
            text_color=("#0066cc", "#6699ff"),
        ).pack(anchor="w", padx=20, pady=(0, 2))
        ctk.CTkLabel(
            fprint_frame, text=row2,
            font=("Consolas", 16, "bold"),
            text_color=("#0066cc", "#6699ff"),
        ).pack(anchor="w", padx=20, pady=(0, 10))

        ctk.CTkLabel(
            dlg,
            text="Share these words via another secure channel\nso others can verify your identity.",
            font=("Segoe UI", 10),
            text_color=("#888888", "#666666"),
            justify=tk.CENTER,
        ).pack(pady=(0, 10))

        ctk.CTkButton(
            dlg, text="OK", command=dlg.destroy,
            width=100, corner_radius=8,
        ).pack(pady=(4, 16))

        dlg.bind('<Escape>', lambda e: dlg.destroy())
        self._center_dialog(dlg)
        self.root.wait_window(dlg)

    def _show_own_fingerprint_after_register(self, username=None):
        self._show_own_fingerprint_dialog(
            "Your Identity Fingerprint - Keep It Safe",
            display_name=username,
        )

    def _show_user_fingerprint_dialog(self, username, fingerprint, words=None):
        if words is None:
            from src.common.crypto_utils import FingerprintWords
            words = FingerprintWords.fingerprint_to_words(fingerprint, 6)
        words_list = words if words else ["??????"] * 6

        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Verify User Identity")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("600x440")
        dlg.resizable(True, True)

        # Warning banner
        warn_frame = ctk.CTkFrame(dlg, fg_color=("#e65100", "#bf360c"), corner_radius=8)
        warn_frame.pack(fill=tk.X, padx=20, pady=(20, 12))
        ctk.CTkLabel(
            warn_frame,
            text=f"\u26a0\ufe0f  VERIFY {username}'S IDENTITY",
            font=("Segoe UI", 14, "bold"), text_color="white",
        ).pack(pady=(12, 4))
        ctk.CTkLabel(
            warn_frame,
            text="Confirm these words match before trusting.",
            font=("Segoe UI", 10), text_color="#ffcc80", justify=tk.CENTER,
        ).pack(pady=(0, 12))

        fprint_frame = ctk.CTkFrame(dlg, fg_color=("#f5f5f5", "#1a1a2e"), corner_radius=10)
        fprint_frame.pack(pady=(4, 12), padx=20, fill=tk.X)
        ctk.CTkLabel(
            fprint_frame,
            text="FINGERPRINT WORDS (BIP39):",
            font=("Segoe UI", 10, "bold"),
            text_color=("#666666", "#888888"),
        ).pack(anchor="w", pady=(10, 8), padx=16)

        row1 = "    ".join(words_list[:3]).upper()
        row2 = "    ".join(words_list[3:6]).upper()
        ctk.CTkLabel(
            fprint_frame, text=row1,
            font=("Consolas", 16, "bold"),
            text_color=("#0066cc", "#6699ff"),
        ).pack(anchor="w", padx=20, pady=(0, 2))
        ctk.CTkLabel(
            fprint_frame, text=row2,
            font=("Consolas", 16, "bold"),
            text_color=("#0066cc", "#6699ff"),
        ).pack(anchor="w", padx=20, pady=(0, 10))

        ctk.CTkLabel(
            dlg,
            text="\u26a0  Confirm via another secure channel\n    (phone call, in person) before trusting.",
            font=("Segoe UI", 9),
            text_color=("#e65100", "#ff9800"),
            justify=tk.CENTER,
        ).pack(pady=(0, 12))

        result = [False]

        def approve():
            result[0] = True
            dlg.destroy()

        def reject():
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=(4, 16))
        ctk.CTkButton(
            btn_frame, text="Trust User", command=approve,
            width=130, corner_radius=8, height=36,
            fg_color=("#2e7d32", "#388e3c"),
            hover_color=("#1b5e20", "#2e7d32"),
            font=("Segoe UI", 12, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 12))
        ctk.CTkButton(
            btn_frame, text="Reject", command=reject,
            width=100, corner_radius=8, height=36,
            fg_color=("#d32f2f", "#b71c1c"),
            hover_color=("#c62828", "#8e0000"),
            font=("Segoe UI", 12),
        ).pack(side=tk.LEFT)

        dlg.bind('<Escape>', lambda e: reject())
        self._center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    # ==================================================================
    # Recovery Key Dialog (after registration)
    # ==================================================================
    def _show_recovery_key_dialog(self):
        """Show recovery key backup dialog after successful registration."""
        if not hasattr(self.client, 'recovery_priv') or not self.client.recovery_priv:
            return
        username = self.client.username or "you"
        recovery_path = f'local_keys/{username}_recovery.priv'

        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Recovery Key Backup")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("540x400")
        dlg.resizable(True, True)

        # Red warning banner
        warn_frame = ctk.CTkFrame(dlg, fg_color=("#d32f2f", "#b71c1c"), corner_radius=8)
        warn_frame.pack(fill=tk.X, padx=20, pady=(20, 12))
        ctk.CTkLabel(
            warn_frame,
            text="\u26d4  STORE THIS KEY SAFELY",
            font=("Segoe UI", 14, "bold"), text_color="white",
        ).pack(pady=(12, 4))
        ctk.CTkLabel(
            warn_frame,
            text="If lost, your account cannot be frozen\nif compromised. IRREVERSIBLE.",
            font=("Segoe UI", 10), text_color="#ffcccc", justify=tk.CENTER,
        ).pack(pady=(0, 12))

        # Key location
        ctk.CTkLabel(
            dlg, text="\U0001f4c1  Key saved to:",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=20, pady=(8, 4))

        path_frame = ctk.CTkFrame(dlg, fg_color=("#f0f0f0", "#2a2a3a"), corner_radius=6)
        path_frame.pack(fill=tk.X, padx=20, pady=(0, 12))
        ctk.CTkLabel(
            path_frame, text=recovery_path,
            font=("Consolas", 11),
            text_color=("#333333", "#cccccc"),
        ).pack(pady=10, padx=12)

        # Warning text
        ctk.CTkLabel(
            dlg,
            text="This key can permanently freeze your account if it's\never compromised. Store it offline (USB drive, paper, or\npassword manager).",
            font=("Segoe UI", 11),
            text_color=("#888888", "#aaaaaa"),
            justify=tk.LEFT,
        ).pack(padx=20, pady=(4, 16))

        ctk.CTkButton(
            dlg, text="I've saved my recovery key",
            command=dlg.destroy,
            width=240, corner_radius=8, height=38,
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(0, 16))

        dlg.bind('<Escape>', lambda e: dlg.destroy())
        self._center_dialog(dlg)
        self.root.wait_window(dlg)

    # ==================================================================
    # About Dialog
    # ==================================================================
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
            "\u2022  cryptography (Apache 2.0)\n"
            "\u2022  pystray (LGPLv3)\n"
            "\u2022  PIL (MIT derivative)\n"
            "\u2022  CustomTkinter (MIT)"
        )
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("About KaleidoTalk")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("480x420")
        dlg.resizable(True, True)

        ctk.CTkLabel(
            dlg, text="\U0001f510  KaleidoTalk",
            font=("Segoe UI", 16, "bold"),
            text_color=("#1a73e8", "#8ab4f8"),
        ).pack(pady=(20, 4))

        ctk.CTkLabel(
            dlg, text=about_text,
            font=("Segoe UI", 10),
            wraplength=420, justify=tk.LEFT,
        ).pack(pady=(8, 16), padx=20)

        ctk.CTkButton(
            dlg, text="OK", command=dlg.destroy,
            width=100, corner_radius=8,
        ).pack(pady=(0, 16))

        dlg.bind('<Escape>', lambda e: dlg.destroy())
        self._center_dialog(dlg)
        self.root.wait_window(dlg)

    # ==================================================================
    # Emergency Freeze Dialog (unchanged from V3.0)
    # ==================================================================
    def _dialog_freeze_account(self):
        """Open emergency freeze dialog."""
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("Freeze Your KaleidoTalk Account")
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
            text="\u26a0\ufe0f  PERMANENT ACCOUNT FREEZE",
            font=("Segoe UI", 14, "bold"), text_color="white",
        ).pack(pady=(12, 6))
        ctk.CTkLabel(
            warn_frame,
            text="This action is IRREVERSIBLE. Once frozen,\nthe account can never be logged in or recovered.",
            font=("Segoe UI", 10), text_color="#ffcccc", justify=tk.CENTER,
        ).pack(pady=(0, 12))

        # Username
        ctk.CTkLabel(dlg, text="Username", font=("Segoe UI", 11)).pack(pady=(4, 4), padx=30, anchor="w")
        user_var = tk.StringVar()
        user_entry = ctk.CTkEntry(dlg, textvariable=user_var, width=440, corner_radius=8, font=("Segoe UI", 11))
        user_entry.pack(pady=(0, 12), padx=30)
        user_entry.focus_set()

        # Recovery key file
        ctk.CTkLabel(dlg, text="Recovery Key File", font=("Segoe UI", 11)).pack(pady=(0, 4), padx=30, anchor="w")
        key_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        key_frame.pack(fill=tk.X, padx=30)
        key_var = tk.StringVar()
        key_entry = ctk.CTkEntry(key_frame, textvariable=key_var, width=340, corner_radius=8, state="readonly")
        key_entry.pack(side=tk.LEFT)

        ctk.CTkButton(key_frame, text="Browse", command=lambda: self._browse_key(key_var, dlg),
                      width=80, corner_radius=8).pack(side=tk.LEFT, padx=(8, 0))

        # Confirmation checkbox
        confirm_var = tk.BooleanVar(value=False)
        confirm_cb = ctk.CTkCheckBox(
            dlg,
            text="I understand this action is irreversible.",
            variable=confirm_var, font=("Segoe UI", 11),
        )
        confirm_cb.pack(pady=(20, 8), padx=30, anchor="w")

        # Freeze button
        freeze_btn = ctk.CTkButton(
            dlg, text="Freeze Account", fg_color="#d32f2f", hover_color="#b71c1c",
            corner_radius=8, state="disabled", width=200, height=38,
            font=("Segoe UI", 12, "bold"),
        )
        freeze_btn.pack(pady=(6, 6))

        ctk.CTkButton(
            dlg, text="Cancel", command=dlg.destroy, corner_radius=8, width=120,
        ).pack(pady=(0, 20))

        dlg.bind('<Escape>', lambda e: dlg.destroy())

        def on_check():
            freeze_btn.configure(state="normal" if confirm_var.get() else "disabled")

        confirm_cb.configure(command=on_check)
        freeze_btn.configure(command=lambda: self._do_freeze(user_var.get().strip(), key_var.get().strip(), dlg))

        self._center_dialog(dlg)
        dlg.update_idletasks()
        user_entry.focus_force()
        self.root.wait_window(dlg)

    def _browse_key(self, key_var, dlg):
        path = filedialog.askopenfilename(
            parent=dlg, title="Select Recovery Key",
            filetypes=[("Private key files", "*.priv"), ("All files", "*.*")],
        )
        if path:
            key_var.set(path)

    def _do_freeze(self, username, key_path, dlg):
        """Attempt to permanently freeze an account using the recovery key."""
        if not username:
            self._dialog_showerror("Error", "Username cannot be empty")
            return
        if not key_path or not os.path.exists(key_path):
            self._dialog_showerror("Error", "Invalid recovery key file")
            return

        try:
            with open(key_path, "r", encoding="utf-8") as f:
                pem_data = f.read()
            recovery_priv = serialization.load_pem_private_key(
                pem_data.encode("utf-8"), password=None, backend=default_backend()
            )
        except Exception:
            self._dialog_showerror("Error", "Invalid recovery key file (not a valid PEM key)")
            return

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
            receiver.recv(tls_sock)

            freeze_ts = int(time.time())
            nonce = secrets.token_hex(16)
            data_to_sign = f"{username}{freeze_ts}{nonce}".encode("utf-8")
            signature = recovery_priv.sign(data_to_sign).hex()

            cmd = {
                "cmd": "freeze_account",
                "data": {
                    "username": username, "timestamp": freeze_ts,
                    "nonce": nonce, "signature": signature,
                },
            }
            PaddedSender.send(tls_sock, json.dumps(cmd, ensure_ascii=False).encode("utf-8"))

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
                    f"\u2705  Account '{username}' has been permanently frozen.\n\nThis account can never be logged in again.",
                )
            else:
                self._dialog_showerror("Freeze Failed", resp.get("error", "Unknown error"))
        except Exception as e:
            self._dialog_showerror("Error", f"Freeze failed: {e}")
        finally:
            try:
                tls_sock.close()
            except Exception:
                pass

    # ==================================================================
    # User Label Click (show fingerprint)
    # ==================================================================
    def _on_user_label_click(self, event):
        if self.client.id_pub:
            self._show_own_fingerprint_dialog(display_name=self.client.username)
        else:
            self._dialog_showinfo("Info", "Identity information not ready")

    # ==================================================================
    # Tray and Exit
    # ==================================================================
    def on_closing(self):
        self._quit_application()

    def on_window_unmap(self, event):
        if (not self.is_exiting and not self.is_minimized_to_tray
                and not self._tray_minimize_pending
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
            pystray.MenuItem('Exit', lambda: self.root.after(0, self._quit_application)),
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
        try:
            geo = self.root.geometry()
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